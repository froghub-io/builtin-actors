use fevm_test_vectors::{load_evm_contract_input, to_message};
use fevm_test_vectors::types::{ContractParams, CreateParams, EvmContractInput};
use fevm_test_vectors::util::{get_test_code_cid_map, is_create_contract};
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_encoding::{BytesDe, RawBytes};
use fil_actors_runtime::test_utils::ACTOR_CODES;

#[test]
fn exec_contract() {
    let inputs: [EvmContractInput; 1] = [
        // serde_json::from_str(include_str!("contracts/contract1.json")).unwrap(),
        serde_json::from_str(include_str!("contracts/contract.json")).unwrap(),
        // serde_json::from_str(include_str!("contracts/contract3.json")).unwrap(),
    ];
    for input in inputs {
        println!("--- input ---");
        let store = MemoryBlockstore::new();
        let actor_codes = get_test_code_cid_map().unwrap();
        let (pre_state_root, _, _) = load_evm_contract_input(&store, actor_codes, &input).expect("failed to load evm contract input");

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
                    Some(CreateParams { initcode: params2.initcode, nonce: params2.nonce }),
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
                    Some(params),
                )
                .unwrap();
            println!("{:?}", call_result);

            let BytesDe(return_value) =
                call_result.ret.deserialize().expect("failed to deserialize results");
            let result = hex::encode(return_value);

            assert_eq!(result, input.context.return_result);
        }
    }
}