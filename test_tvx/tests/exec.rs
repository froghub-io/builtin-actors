use fil_actor_eam::EthAddress;
use fil_actors_runtime::test_utils::ACTOR_CODES;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::{strict_bytes, BytesDe, Cbor, RawBytes};
use serde::{Deserialize, Serialize};
use serde_tuple::*;
use std::path::Path;
use test_tvx::mock_single_actors::{ContractParams, CreateParams, print_actor_state, to_message};
use test_tvx::{compute_address_create, is_create_contract, string_to_eth_address, EvmContractInput};
use test_tvx::{export_test_vector_file, load_evm_contract_input};

#[test]
fn evm_create_test() {
    let from = string_to_eth_address("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54");
    let expected = string_to_eth_address("0xcc3d7ca4a302d196e70760e772ee26d38bd09dca");
    let result = compute_address_create(&EthAddress(from.0), 1);
    assert_eq!(result.0[..], expected.0[..]);
}

#[async_std::test]
async fn exec_export() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();
    export_test_vector_file(
        input,
        Path::new("/Users/grw/Desktop/constract2_test_vector.json").to_path_buf(),
    )
    .await
    .unwrap();
}

#[test]
fn exec_contract() {
    let inputs: [EvmContractInput; 3] = [
        serde_json::from_str(include_str!("contracts/contract1.json")).unwrap(),
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap(),
        serde_json::from_str(include_str!("contracts/contract3.json")).unwrap(),
    ];
    for input in inputs {
        println!("--- input ---");
        let store = MemoryBlockstore::new();
        let (pre_state_root, _) = load_evm_contract_input(&store, ACTOR_CODES.clone(), &input).expect("failed to load evm contract input");

        let message = to_message(&input.context);

        let vm = test_vm::VM::new(&store);
        vm.state_root.replace(pre_state_root);

        if is_create_contract(&input.context.to) {
            let params2: CreateParams = RawBytes::deserialize(&message.params).unwrap();
            let create_result = vm
                .apply_message(
                    message.from,
                    message.to,
                    message.value,
                    fil_actor_eam::Method::Create as u64,
                    CreateParams { initcode: params2.initcode, nonce: params2.nonce },
                )
                .unwrap();
            println!("{:?}", create_result);

            assert!(
                create_result.code.is_success(),
                "failed to create the new actor {}",
                create_result.message
            );
        } else {
            let params: ContractParams = RawBytes::deserialize(&message.params.into()).unwrap();
            let call_result = vm
                .apply_message(
                    message.from,
                    message.to,
                    message.value,
                    fil_actor_evm::Method::InvokeContract as u64,
                    params,
                )
                .unwrap();
            println!("{:?}", call_result);

            let BytesDe(return_value) =
                call_result.ret.deserialize().expect("failed to deserialize results");
            let result = hex::encode(return_value);

            assert_eq!(result, input.context.return_result);
        }

        print_actor_state(vm.state_root.borrow().clone(), &store).expect("failed to print actor state");
    }
}