use crate::mock_single_actors::Mock;
use crate::tracing_blockstore::TracingBlockStore;
use async_std::channel::bounded;
use async_std::io::Cursor;
use async_std::sync::RwLock;
use bytes::Buf;
use cid::multihash::Code;
use cid::multihash::MultihashDigest;
use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_evm::interpreter::U256;
use flate2::bufread::GzDecoder;
use flate2::bufread::GzEncoder;
use flate2::Compression;
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_ipld_car::CarHeader;
use fvm_ipld_encoding::Cbor;
use fvm_ipld_encoding::RawBytes;
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
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufWriter;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
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
    let (pre_state_root, post_state_root, message, receipt, bytes) = export(input).await;
    let variants = vec![Variant {
        id: String::from("test_evm"),
        epoch: 2383680,
        nv: NetworkVersion::V18 as u32,
    }];
    let test_vector = TestVector {
        class: String::from_str("message")?,
        selector: None,
        meta: None,
        car: bytes,
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
        randomness: fvm_shared::randomness::Randomness(vec![0u8; RANDOMNESS_LENGTH]),
    };

    let output = File::create(&path)?;
    serde_json::to_writer_pretty(output, &test_vector)?;
    Ok(())
}

pub async fn export(input: EvmContractInput) -> (Cid, Cid, Message, Receipt, Vec<u8>) {
    let store = TracingBlockStore::new(MemoryBlockstore::new());
    let mut mock = Mock::new(&store);
    mock.mock_builtin_actor();

    let from = Address::new_delegated(10, &string_to_eth_address(&input.context.from).0).unwrap();
    mock.mock_embryo_address_actor(from, TokenAmount::zero());

    // preconditions
    for (eth_addr, state) in &input.states {
        let eth_addr = string_to_eth_address(&eth_addr);
        let to = Address::new_delegated(10, &eth_addr.0).unwrap();
        if is_create_contract(&input.context.to)
            && eth_addr.eq(&compute_address_create(
                &string_to_eth_address(&input.context.from),
                input.context.nonce,
            ))
        {
            continue;
        }
        mock.mock_evm_actor(to, TokenAmount::zero());

        let mut storage = HashMap::<U256, U256>::new();
        for (k, v) in &state.partial_storage_before {
            let key = string_to_U256(&k);
            let value = string_to_U256(&v);
            storage.insert(key, value);
        }
        let bytecode = string_to_bytes(&state.code);
        mock.mock_evm_actor_state(to, storage, Some(bytecode));
    }
    let pre_state_root = mock.get_state_root();
    println!("pre_state_root: {:?}", pre_state_root);

    // postconditions
    for (eth_addr, state) in &input.states {
        let eth_addr = string_to_eth_address(&eth_addr);
        let to = Address::new_delegated(10, &eth_addr.0).unwrap();
        if is_create_contract(&input.context.to)
            && eth_addr.eq(&compute_address_create(
                &string_to_eth_address(&input.context.from),
                input.context.nonce,
            ))
        {
            mock.mock_evm_actor(to, TokenAmount::zero());
        }
        let mut storage = HashMap::<U256, U256>::new();
        for (k, v) in &state.partial_storage_after {
            let key = string_to_U256(&k);
            let value = string_to_U256(&v);
            storage.insert(key, value);
        }
        let bytecode = if is_create_contract(&input.context.to)
            && eth_addr.eq(&compute_address_create(
                &string_to_eth_address(&input.context.from),
                input.context.nonce,
            )) {
            Some(string_to_bytes(&state.code))
        } else {
            None
        };
        mock.mock_evm_actor_state(to, storage, bytecode);
    }

    let post_state_root = mock.get_state_root();
    println!("post_state_root: {:?}", post_state_root);

    let message = mock.to_message(&input.context);

    println!("message: {:?}", message);

    let receipt = Receipt {
        exit_code: ExitCode::OK,
        return_data: RawBytes::serialize(hex::decode(&input.context.return_result).unwrap())
            .unwrap(),
        gas_used: 0,
        events_root: None,
    };

    println!("receipt: {:?}", receipt);

    let (tx, mut rx) = bounded(100);
    let state_root = mock.get_state_root();
    let car_header = CarHeader::new(vec![state_root], 1);
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

    let mut gz_car_bytes: Vec<u8> = Default::default();
    let mut gz_encoder = GzEncoder::new(car_bytes.reader(), Compression::new(9));
    gz_encoder.read_to_end(&mut gz_car_bytes).unwrap();

    let mut gz_decoder = GzDecoder::new(gz_car_bytes.as_slice());

    let mut car_bytes: Vec<u8> = Default::default();
    gz_decoder.read_to_end(&mut car_bytes).unwrap();

    println!("gz_car_bytes: {:?}", gz_car_bytes);

    (pre_state_root, post_state_root, message, receipt, gz_car_bytes)
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

pub fn string_to_U256(str: &str) -> U256 {
    let v = string_to_bytes(str);
    let mut r = [0u8; 32];
    r[32 - v.len()..32].copy_from_slice(&v);
    U256::from_big_endian(&r)
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

pub fn U256_to_bytes(u: &U256) -> Vec<u8> {
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
    pub context: EvmContractContext,
}

impl EvmContractInput {
    pub fn find_state(&self, eth_addr: EthAddress) -> Option<&EvmContractState> {
        for k in self.states.keys() {
            if string_to_eth_address(k).eq(&eth_addr) {
                return self.states.get(&k.clone());
            }
        }
        None
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractState {
    pub partial_storage_before: HashMap<String, String>,
    pub partial_storage_after: HashMap<String, String>,
    pub code: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EvmContractContext {
    pub from: String,
    pub to: String,
    pub input: String,
    pub value: ValueType,
    pub block_number: usize,
    pub timestamp: usize,
    pub nonce: u64,
    pub block_hash: String,
    pub block_difficulty: usize,
    pub status: usize,
    #[serde(alias = "return")]
    pub return_result: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ValueType {
    #[serde(alias = "type")]
    pub v_type: String,
    pub hex: String,
}
