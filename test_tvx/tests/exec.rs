use fil_actor_eam as eam;
use fil_actor_eam::{EthAddress, EvmConstructorParams, RlpCreateAddress};
use fil_actor_init::ExecReturn;
use fil_actors_runtime::test_utils::MULTISIG_ACTOR_CODE_ID;
use fil_actors_runtime::{
    cbor, EAM_ACTOR_ADDR, EAM_ACTOR_ID, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR, SYSTEM_ACTOR_ID,
};
// use fvm::machine::Manifest;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::{strict_bytes, BytesDe, Cbor, CborStore, RawBytes};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::METHOD_SEND;
use multihash::Code;
use num_traits::Zero;
use rlp::Encodable;
use serde::{Deserialize, Serialize};
use serde_tuple::*;
use std::cell::RefCell;
use std::{env, fs};
use std::collections::HashMap;
use std::str::FromStr;
use cid::Cid;
use fil_actor_evm::interpreter::U256;
use test_tvx::mock_single_actors::Mock;
use test_tvx::util::create_account;
use test_tvx::{string_to_ETHAddress, string_to_U256, string_to_bytes, EvmContractInput, FAUCET_ROOT_KEY, VM, EvmContractState};
use test_vm::util::apply_ok;
use test_vm::{TEST_FAUCET_ADDR, TEST_VERIFREG_ROOT_SIGNER_ADDR, VERIFREG_ROOT_KEY};

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
    // v.manual_construct_for_participants(account);

    let construct_eth_addr = string_to_ETHAddress("0x00".to_string());
    let mut salt = [0u8; 32];
    salt[..20].copy_from_slice(&construct_eth_addr.0);

    let initcode = string_to_bytes(input.context.input.clone());
    println!("account: {:?}", account);
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

    // let storage = v.get_participants_store();
    // for (addr, state) in input.states {
    //     let eth_addr = string_to_ETHAddress(addr);
    //     for (k, v) in state.partial_storage_after {
    //         let uk = string_to_U256(k);
    //         let uv = string_to_U256(v);
    //         let store =
    //             storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
    //         let sv = store.get(&uk).expect("contract state key not exist").clone();
    //         assert_eq!(uv, sv);
    //     }
    // }
}

#[test]
fn mock_single_actor_blockstore() {
    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_system_actor();
    mock.mock_init_actor();

    let eth_addr = Address::new_delegated(
        EAM_ACTOR_ID,
        &string_to_ETHAddress(String::from("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54")).0,
    ).unwrap();
    mock.mock_embryo_address_actor(eth_addr, TokenAmount::zero());

    // An empty built-in actors manifest.
    // let manifest_cid = { store.put_cbor(&Manifest::DUMMY_CODES, Code::Blake2b256).unwrap() };
    // let actors_cid = store.put_cbor(&(1, manifest_cid), Code::Blake2b256).unwrap();

    let vm = test_vm::VM::new(&store);
    vm.state_root.replace(mock.state_root.into_inner());

    let init_actor = vm.get_actor(INIT_ACTOR_ADDR).unwrap();
    println!("init_actor: {:?}", init_actor);

    let system_actor = vm.get_actor(SYSTEM_ACTOR_ADDR).unwrap();
    println!("system_actor: {:?}", system_actor);

    // create a faucet with 1 billion FIL for setting up test accounts
    let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
    let faucet_addr = Address::new_bls(FAUCET_ROOT_KEY).unwrap();
    apply_ok(&vm, SYSTEM_ACTOR_ADDR, faucet_addr, faucet_total, METHOD_SEND, RawBytes::default());

    let send_amount = TokenAmount::from_whole(1);
    apply_ok(&vm, faucet_addr, eth_addr, send_amount.clone(), METHOD_SEND, RawBytes::default());

    assert_eq!(
        send_amount.clone(),
        vm.get_actor(vm.normalize_address(&eth_addr).unwrap()).unwrap().balance
    );
}

#[test]
fn exec_contract_k() {
    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_system_actor();
    mock.mock_init_actor();

    let eth_addr1 = Address::new_delegated(
        10,
        &string_to_ETHAddress(String::from("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54")).0,
    ).unwrap();
    mock.mock_embryo_address_actor(eth_addr1, TokenAmount::zero());

    let delegated_addr2 = Address::new_delegated(
        10,
        &string_to_ETHAddress(String::from("0x00")).0,
    ).unwrap();
    mock.mock_evm_actor(delegated_addr2, TokenAmount::zero());

    // println!("{:?}", state);

    // let vm = test_vm::VM::new(&store);
    // let cid = Cid::from_str("bafy2bzacedpgfoy4sqegabrjn2xuqebaeiupm6yndjpy23srpvwuelfokq2xa").unwrap();
    // println!("state_root {:?}", mock.state_root.borrow().to_string());
    // vm.state_root.replace(mock.state_root.into_inner());
    //
    // let input: EvmContractInput = serde_json::from_str(include_str!("contracts/contract1.json")).unwrap();
    // let params = string_to_bytes(input.context.input);
    // let call_result = vm
    //     .apply_message(
    //         Address::new_id(1),
    //         delegated_addr2,
    //         TokenAmount::zero(),
    //         fil_actor_evm::Method::Constructor as u64,
    //         ConstructorParams{
    //             creator: string_to_ETHAddress(String::from("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54")),
    //             initcode: params
    //         },
    //     )
    //     .unwrap();
    // let BytesDe(return_value) =
    //     call_result.ret.deserialize().expect("failed to deserialize results");
    // let result = hex::encode(return_value);

    // println!("return: {:?}", call_result);
}

#[test]
fn exec_contract_blockstore_2() {
    let input: EvmContractInput = serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();

    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_system_actor();
    mock.mock_init_actor();

    let from = Address::new_delegated(
        10,
        &string_to_ETHAddress(String::from("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54")).0,
    ).unwrap();
    mock.mock_embryo_address_actor(from, TokenAmount::zero());

    let to = Address::new_delegated(
        10,
        &string_to_ETHAddress(String::from("0x3471Ff6AFE294B8cF742DbEAbaBE1476759297F0")).0,
    ).unwrap();
    mock.mock_evm_actor(to, TokenAmount::zero());
    let evm_state: EvmContractState = input.states.get(&String::from("0x3471ff6afe294b8cf742dbeababe1476759297f0")).unwrap().clone();
    let mut storage = HashMap::<U256, U256>::new();
    for (k, v) in evm_state.partial_storage_before {
        let key = string_to_U256(k);
        let value = string_to_U256(v);
        storage.insert(key, value);
    }
    let bytecode = string_to_bytes(evm_state.code);
    mock.mock_init_evm_actor_state(to, storage, bytecode);

    let vm = test_vm::VM::new(&store);
    vm.state_root.replace(mock.state_root.into_inner());

    let params = string_to_bytes(input.context.input);
    println!("params {:?}", hex::encode(params.clone()));
    let call_result = vm
        .apply_message(
            from,
            to,
            TokenAmount::zero(),
            fil_actor_evm::Method::InvokeContract as u64,
            ContractParams(params.to_vec()),
        )
        .unwrap();
    let BytesDe(return_value) =
        call_result.ret.deserialize().expect("failed to deserialize results");
    let result = hex::encode(return_value);

    // mock.print_actor_evm_state(to);

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

}

#[test]
fn exec_contract_2() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();
    let store = MemoryBlockstore::new();
    let mut v = VM::new_with_singletons(&store, input.clone());
    let account = create_account(&v, string_to_ETHAddress("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54".to_string()));

    v.manual_construct_for_participants(account);

    let params = string_to_bytes(input.context.input);
    println!("params {:?}", hex::encode(params.clone()));
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
    //
    let storage = v.get_participants_store();
    // for (addr, state) in input.states {
    //     let eth_addr = string_to_ETHAddress(addr);
    //     for (k, v) in state.partial_storage_after {
    //         let uk = string_to_U256(k);
    //         let uv = string_to_U256(v);
    //         let store =
    //             storage.get(&hex::encode(eth_addr.0)).expect("contract state not exist").clone();
    //         let sv = store.get(&uk).expect("contract state key not exist").clone();
    //         assert_eq!(uv, sv);
    //     }
    // }
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
