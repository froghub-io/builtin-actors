use crate::mock_single_actors::Mock;
use crate::tracing_blockstore::TracingBlockStore;
use crate::vector::RandomnessMatch;
use crate::vector::RandomnessRule;
use async_std::channel::bounded;
use async_std::io::Cursor;
use async_std::sync::RwLock;
use bytes::Buf;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_evm::interpreter::U256;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::runtime::EMPTY_ARR_CID;
use flate2::bufread::GzDecoder;
use flate2::bufread::GzEncoder;
use flate2::Compression;
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_ipld_car::CarHeader;
use fvm_ipld_encoding::strict_bytes;
use fvm_ipld_encoding::CborStore;
use fvm_ipld_encoding::RawBytes;
use fvm_ipld_encoding::{BytesDe, BytesSer, Cbor};
use fvm_ipld_hamt::Hamt;
use fvm_shared::address::Address;
use fvm_shared::bigint::{BigInt, Integer};
use fvm_shared::clock::ChainEpoch;
use fvm_shared::crypto::hash::SupportedHashes;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::message::Message;
use fvm_shared::randomness::RANDOMNESS_LENGTH;
use fvm_shared::receipt::Receipt;
use fvm_shared::version::NetworkVersion;
use fvm_shared::HAMT_BIT_WIDTH;
use mock_single_actors::to_message;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use util::get_code_cid_map;
use vector::ApplyMessage;
use vector::PreConditions;
use vector::StateTreeVector;
use vector::TestVector;
use vector::Variant;

mod cidjson;
pub mod mock_single_actors;
pub mod tracing_blockstore;
mod util;
mod vector;

pub async fn export_test_vector_file(input: EvmContractInput, path: PathBuf) -> anyhow::Result<()> {
    let actor_codes = get_code_cid_map()?;
    let store = TracingBlockStore::new(MemoryBlockstore::new());

    let (pre_state_root, post_state_root) = load_evm_contract_input(&store, actor_codes, &input)?;
    let pre_state_root = store.put_cbor(&(5, pre_state_root, EMPTY_ARR_CID), Code::Blake2b256)?;
    let post_state_root = store.put_cbor(&(5, post_state_root, EMPTY_ARR_CID), Code::Blake2b256)?;

    //car_bytes
    let car_header = CarHeader::new(vec![pre_state_root, post_state_root], 1);
    let (tx, mut rx) = bounded(100);
    let buffer: Arc<RwLock<Vec<u8>>> = Default::default();
    let buffer_cloned = buffer.clone();
    let write_task = async_std::task::spawn(async move {
        car_header.write_stream_async(&mut *buffer_cloned.write().await, &mut rx).await.unwrap()
    });
    for cid in (&store).traced.borrow().iter() {
        tx.send((cid.clone(), store.base.get(cid).unwrap().unwrap())).await.unwrap();
    }
    drop(tx);
    write_task.await;
    let car_bytes = buffer.read().await.clone();

    //gzip car_bytes
    let mut gz_car_bytes: Vec<u8> = Default::default();
    let mut gz_encoder = GzEncoder::new(car_bytes.reader(), Compression::new(9));
    gz_encoder.read_to_end(&mut gz_car_bytes).unwrap();

    //message
    let message = to_message(&input.context);

    //receipt
    let receipt = Receipt {
        exit_code: ExitCode::OK,
        return_data: RawBytes::serialize(BytesDe(hex::decode(&input.context.return_result)?))?,
        gas_used: 0,
        events_root: None,
    };
    println!("receipt: {:?}", receipt);

    // let (pre_state_root, post_state_root, message, receipt, bytes) = export(input).await;

    const ENTROPY: &[u8] = b"prevrandao";
    let randomness = vec![RandomnessMatch {
        on: RandomnessRule {
            kind: vector::RandomnessKind::Beacon,
            dst: 10, //fil_actors_runtime::runtime::randomness::DomainSeparationTag::EvmPrevRandao as i64,
            //TODO
            epoch: 2383680,
            entropy: Vec::from(ENTROPY),
        },
        //TODO
        ret: Vec::from([0u8; 32]),
    }];
    let variants = vec![Variant {
        id: String::from("test_evm"),
        epoch: 2383680,
        timestamp: Some(1671507767),
        nv: NetworkVersion::V18 as u32,
    }];
    let test_vector = TestVector {
        class: String::from_str("message")?,
        chain_id: Some(1),
        selector: None,
        meta: None,
        car: gz_car_bytes,
        preconditions: PreConditions {
            state_tree: StateTreeVector { root_cid: pre_state_root },
            basefee: None,
            circ_supply: None,
            variants,
        },
        apply_messages: vec![ApplyMessage { bytes: message.marshal_cbor()?, epoch_offset: None }],
        postconditions: vector::PostConditions {
            state_tree: StateTreeVector { root_cid: post_state_root },
            receipts: vec![receipt],
        },
        tipset_cids: None,
        randomness,
    };

    let output = File::create(&path)?;
    serde_json::to_writer_pretty(output, &test_vector)?;
    Ok(())
}

pub fn get_eth_addr_balance(eth_addr: &String, balances: &HashMap<String, EvmContractBalance>, pre: bool) -> TokenAmount {
    match balances.get(eth_addr) {
        Some(v) => {
            if pre {
                TokenAmount::from_atto(string_to_big_int(&v.pre_balance))
            } else {
                TokenAmount::from_atto(string_to_big_int(&v.post_balance))
            }
        },
        None => TokenAmount::from_atto(0)
    }
}

pub fn load_evm_contract_input<BS>(
    store: &BS,
    actor_codes: BTreeMap<Type, Cid>,
    input: &EvmContractInput,
) -> anyhow::Result<(Cid, Cid)>
where
    BS: Blockstore,
{
    let mut mock = Mock::new(store, actor_codes);
    mock.mock_builtin_actor();

    let from = Address::new_delegated(10, &string_to_eth_address(&input.context.from).0).unwrap();
    let from_nonce = input.context.nonce;
    mock.mock_embryo_address_actor(from, get_eth_addr_balance(&input.context.from, &input.balances, true), from_nonce);

    // preconditions
    for (eth_addr_str, state) in &input.states {
        let eth_addr = string_to_eth_address(&eth_addr_str);
        let to = Address::new_delegated(10, &eth_addr.0).unwrap();
        println!("mock eth_addr: {:?}", to.to_string());

        if is_create_contract(&input.context.to)
            && eth_addr.eq(&compute_address_create(
                &string_to_eth_address(&input.context.from),
                input.context.nonce,
            ))
        {
            continue;
        }
        mock.mock_evm_actor(to, get_eth_addr_balance(eth_addr_str, &input.balances, true));

        let mut storage = HashMap::<U256, U256>::new();
        for (k, v) in &state.pre_storage {
            let key = string_to_u256(&k);
            let value = string_to_u256(&v);
            storage.insert(key, value);
        }
        let bytecode = match &state.pre_code { Some(bytecode) => { Some(string_to_bytes(bytecode)) }, None => None };
        mock.mock_evm_actor_state(&to, storage, bytecode)?;
    }
    let pre_state_root = mock.get_state_root();
    println!("pre_state_root: {:?}", pre_state_root);

    // postconditions
    for (eth_addr, state) in &input.states {
        let eth_addr = string_to_eth_address(&eth_addr);
        let to = Address::new_delegated(10, &eth_addr.0).unwrap();
        mock.mock_evm_actor(to, TokenAmount::zero());
        let mut storage = HashMap::<U256, U256>::new();
        for (k, v) in &state.post_storage {
            let key = string_to_u256(&k);
            let value = string_to_u256(&v);
            storage.insert(key, value);
        }
        let bytecode = match &state.post_code { Some(bytecode) => { Some(string_to_bytes(bytecode)) }, None => None };
        mock.mock_evm_actor_state(&to, storage, bytecode)?;
    }

    let post_state_root = mock.get_state_root();
    println!("post_state_root: {:?}", post_state_root);

    return Ok((pre_state_root, post_state_root));
}

pub fn compute_address_create(from: &EthAddress, nonce: u64) -> EthAddress {
    let mut stream = rlp::RlpStream::new();
    stream.begin_list(2).append(&&from.0[..]).append(&nonce);
    EthAddress(hash_20(&stream.out()))
}

pub fn hash_20(data: &[u8]) -> [u8; 20] {
    hash(SupportedHashes::Keccak256, data)[12..32].try_into().unwrap()
}

pub fn hash(hasher: SupportedHashes, data: &[u8]) -> Vec<u8> {
    let hasher = Code::try_from(hasher as u64).unwrap();
    let (_, digest, written) = hasher.digest(data).into_inner();
    Vec::from(&digest[..written as usize])
}

pub fn string_to_u256(str: &str) -> U256 {
    let v = string_to_bytes(str);
    let mut r = [0u8; 32];
    r[32 - v.len()..32].copy_from_slice(&v);
    U256::from_big_endian(&r)
}

pub fn string_to_i64(str: &str) -> i64 {
    let v = string_to_bytes(str);
    i64::from_str(&*hex::encode(v)).unwrap()
}

pub fn string_to_big_int(str: &str) -> BigInt {
    let v = string_to_bytes(str);
    BigInt::from_str(&*hex::encode(v)).unwrap()
}

pub fn string_to_eth_address(str: &str) -> EthAddress {
    let v = string_to_bytes(str);
    let mut r = [0u8; 20];
    r[20 - v.len()..20].copy_from_slice(&v);
    EthAddress(r)
}

pub fn string_to_bytes(str: &str) -> Vec<u8> {
    if str.starts_with("0x") {
        let str = &str[2..str.len()];
        hex::decode(if str.len().is_odd() {
            let mut s = String::from("0");
            s.push_str(str);
            s
        } else {
            str.to_string()
        })
        .unwrap()
    } else {
        hex::decode(if str.len().is_odd() {
            let mut s = String::from("0");
            s.push_str(&str);
            s
        } else {
            str.to_string()
        })
        .unwrap()
    }
}

pub fn u256_to_bytes(u: &U256) -> Vec<u8> {
    let mut v = vec![0u8; 32];
    (0..4).for_each(|i| {
        let e = hex::decode(hex::encode(u.0[3 - i].to_be_bytes())).unwrap();
        v[i * 8..(i + 1) * 8].copy_from_slice(&e);
    });
    v
}

pub fn is_create_contract(to: &str) -> bool {
    // to: 0x00
    if string_to_eth_address("0x00").eq(&string_to_eth_address(to)) {
        true
    } else {
        false
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractInput {
    pub states: HashMap<String, EvmContractState>,
    pub balances: HashMap<String, EvmContractBalance>,
    pub transactions: Vec<String>,
    pub context: EvmContractContext,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractState {
    pub pre_storage: HashMap<String, String>,
    pub post_storage: HashMap<String, String>,
    pub pre_code: Option<String>,
    pub post_code: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractBalance {
    pub pre_balance: String,
    pub post_balance: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractTransaction {
    pub block_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractContext {
    pub chain_id: u64,
    pub from: String,
    pub to: String,
    pub input: String,
    pub value: String,
    pub gas_limit: u64,
    pub gas_price: String,
    pub gas_fee_cap: String,
    pub gas_tip_cap: String,
    pub block_number: u64,
    pub timestamp: usize,
    pub nonce: u64,
    pub block_hash: String,
    pub block_difficulty: usize,
    pub status: usize,
    #[serde(alias = "return")]
    pub return_result: String,
}
