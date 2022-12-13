use fil_actor_eam as eam;
use fil_actor_eam::{EvmConstructorParams, RlpCreateAddress};
use fil_actor_evm::interpreter::address::EthAddress;
use fil_actors_runtime::{cbor, EAM_ACTOR_ADDR, SYSTEM_ACTOR_ADDR, SYSTEM_ACTOR_ID};
// use fvm::machine::Manifest;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::{strict_bytes, BytesDe, Cbor, CborStore, RawBytes};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use multihash::Code;
use num_traits::Zero;
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use serde_tuple::*;
use std::cell::RefCell;
use std::{env, fs};
use test_tvx::mock_single_actors::Mock;
use test_tvx::util::create_account;
use test_tvx::{
    string_to_ETHAddress, string_to_U256, string_to_bytes, EvmContractInput, FAUCET_ROOT_KEY, VM,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct ContractParams(#[serde(with = "strict_bytes")] pub Vec<u8>);

impl Cbor for ContractParams {}

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct ConstructorParams {
    pub creator: EthAddress,
    #[serde(with = "strict_bytes")]
    pub initcode: Vec<u8>,
}

impl Cbor for ConstructorParams {}

#[test]
fn exec_rlp_test() {
    let eth_addr = string_to_ETHAddress("443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54".to_string());
    let rlp = RlpCreateAddress { address: eth_addr, nonce: 1 };
    let rlp_hex = hex::encode(rlp.rlp_bytes());
    let go_rlp_hex = "d694443c0c6f6cb301b49ee5e9be07b867378e73fb5401";
    assert_eq!(rlp_hex, go_rlp_hex);
    //TODO: error in rlp parsing result, repair required
}

#[test]
fn exec_contract_for_env() {
    // such as: export INPUT_EVM_CONTRACT_DATA=xxx.json
    let input_evm_contract_data = env::var("INPUT_EVM_CONTRACT_DATA")
        .expect("Please set the environment variable (env: INPUT_EVM_CONTRACT_DATA) ");
    let input_evm_contract_content = fs::read_to_string(input_evm_contract_data).unwrap();
    let input: EvmContractInput = serde_json::from_str(&input_evm_contract_content).unwrap();

    let store = MemoryBlockstore::new();
    let mut v = VM::new_with_singletons(&store, input.clone());
    let account = create_account(&v, string_to_ETHAddress(input.context.from));

    v.manual_construct_for_participants(account);

    let construct_eth_addr = v.find_construct_eth_addr();

    let result = if let Some(construct_eth_addr) = construct_eth_addr {
        let mut salt = [0u8; 32];
        salt[..20].copy_from_slice(&construct_eth_addr.0);
        let initcode = string_to_bytes(input.context.input.clone());
        let create_result = v
            .apply_message(
                account,
                EAM_ACTOR_ADDR,
                TokenAmount::zero(),
                fil_actor_eam::Method::Create2 as u64,
                fil_actor_eam::Create2Params { initcode, salt },
            )
            .unwrap();
        let actor: fil_actor_eam::Create2Return =
            create_result.ret.deserialize().expect("failed to decode results");
        v.add_participants(actor);

        let bytecode = v
            .get_participant_bytecode(account, string_to_ETHAddress("0x00".to_string()))
            .expect("bytecode not found");
        hex::encode(bytecode)
    } else {
        let params = string_to_bytes(input.context.input);
        let call_result = v
            .apply_message(
                account,
                v.to_addr(input.context.to).expect("address not fount"),
                TokenAmount::zero(),
                fil_actor_evm::Method::InvokeContract as u64,
                ContractParams(params.to_vec()),
            )
            .unwrap();
        let BytesDe(return_value) =
            call_result.ret.deserialize().expect("failed to deserialize results");
        hex::encode(return_value)
    };

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

    let storage = v.get_participants_store();
    for (addr, state) in input.states {
        let eth_addr = string_to_ETHAddress(addr);
        for (k, v) in state.partial_storage_after {
            let uk = string_to_U256(k);
            let uv = string_to_U256(v);
            let store =
                storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
            let sv = store.get(&uk).expect("contract state key not exist").clone();
            assert_eq!(uv, sv);
        }
    }
}

#[test]
fn exec_contract_1() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract1.json")).unwrap();
    let store = MemoryBlockstore::new();
    let mut v = VM::new_with_singletons(&store, input.clone());
    let account = create_account(&v, string_to_ETHAddress(input.context.from));

    //TODO: The rlp is not parsed correctly. You can pass the test only after the repair is completed
    v.manual_construct_for_participants(account);

    let construct_eth_addr = v.find_construct_eth_addr().unwrap();
    let mut salt = [0u8; 32];
    salt[..20].copy_from_slice(&construct_eth_addr.0);

    let initcode = string_to_bytes(input.context.input.clone());
    let create_result = v
        .apply_message(
            account,
            EAM_ACTOR_ADDR,
            TokenAmount::zero(),
            fil_actor_eam::Method::Create2 as u64,
            fil_actor_eam::Create2Params { initcode, salt },
        )
        .unwrap();
    let actor: fil_actor_eam::Create2Return =
        create_result.ret.deserialize().expect("failed to decode results");
    v.add_participants(actor);

    let bytecode = v
        .get_participant_bytecode(account, string_to_ETHAddress("0x00".to_string()))
        .expect("bytecode not found");
    let result = hex::encode(bytecode);

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

    let storage = v.get_participants_store();
    for (addr, state) in input.states {
        let eth_addr = string_to_ETHAddress(addr);
        for (k, v) in state.partial_storage_after {
            let uk = string_to_U256(k);
            let uv = string_to_U256(v);
            let store =
                storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
            let sv = store.get(&uk).expect("contract state key not exist").clone();
            assert_eq!(uv, sv);
        }
    }
}

#[test]
fn exec_contract_2() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();
    let store = MemoryBlockstore::new();
    let mut v = VM::new_with_singletons(&store, input.clone());
    let account = create_account(&v, string_to_ETHAddress(input.context.from));

    v.manual_construct_for_participants(account);

    let params = string_to_bytes(input.context.input);
    let call_result = v
        .apply_message(
            account,
            v.to_addr(input.context.to).expect("address not fount"),
            TokenAmount::zero(),
            fil_actor_evm::Method::InvokeContract as u64,
            ContractParams(params.to_vec()),
        )
        .unwrap();
    let BytesDe(return_value) =
        call_result.ret.deserialize().expect("failed to deserialize results");
    let result = hex::encode(return_value);

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

    let storage = v.get_participants_store();
    for (addr, state) in input.states {
        let eth_addr = string_to_ETHAddress(addr);
        for (k, v) in state.partial_storage_after {
            let uk = string_to_U256(k);
            let uv = string_to_U256(v);
            let store =
                storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
            let sv = store.get(&uk).expect("contract state key not exist").clone();
            assert_eq!(uv, sv);
        }
    }
}

#[test]
fn mock_single_actor_blockstore() {
    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_system_actor();
    mock.mock_init_actor();

    // An empty built-in actors manifest.
    // let manifest_cid = { store.put_cbor(&Manifest::DUMMY_CODES, Code::Blake2b256).unwrap() };
    // let actors_cid = store.put_cbor(&(1, manifest_cid), Code::Blake2b256).unwrap();

    let vm = test_vm::VM::new(&store);
    vm.state_root.replace(mock.state_root.into_inner());
    let init_actor = vm.get_actor(SYSTEM_ACTOR_ADDR).unwrap();
    println!("init_actor: {:?}", init_actor);
}

#[test]
fn exec_contract_3() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract3.json")).unwrap();
    let store = MemoryBlockstore::new();
    let mut v = VM::new_with_singletons(&store, input.clone());
    let account = create_account(&v, string_to_ETHAddress(input.context.from));

    v.manual_construct_for_participants(account);

    let params = string_to_bytes(input.context.input);
    let call_result = v
        .apply_message(
            account,
            v.to_addr(input.context.to).expect("address not fount"),
            TokenAmount::zero(),
            fil_actor_evm::Method::InvokeContract as u64,
            ContractParams(params.to_vec()),
        )
        .unwrap();
    let BytesDe(return_value) =
        call_result.ret.deserialize().expect("failed to deserialize results");
    let result = hex::encode(return_value);

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

    let storage = v.get_participants_store();
    for (addr, state) in input.states {
        let eth_addr = string_to_ETHAddress(addr);
        for (k, v) in state.partial_storage_after {
            let uk = string_to_U256(k);
            let uv = string_to_U256(v);
            let store =
                storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
            let sv = store.get(&uk).expect("contract state key not exist").clone();
            assert_eq!(uv, sv);
        }
    }
}
