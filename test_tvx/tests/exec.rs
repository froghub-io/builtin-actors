use async_std::fs::File;
use async_std::io::BufReader;
use fevm_test_vectors::types::{ContractParams, CreateParams};
use fevm_test_vectors::util::{get_test_code_cid_map, u256_to_bytes};
use fevm_test_vectors::{get_evm_actors_slots, load_evm_contract_input, to_message};
use fevm_test_vectors::extractor::types::EthTransactionTestVector;
use fil_actor_evm::interpreter::U256;
use fil_actors_runtime::test_utils::ACTOR_CODES;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_car::load_car;
use fvm_ipld_encoding::{BytesDe, CborStore, RawBytes};
use fvm_shared::state::StateRoot;

#[test]
fn exec_contract() {
    let inputs: [EthTransactionTestVector; 1] =
        [serde_json::from_str(include_str!("contracts/0x26c9c5e5e4f35e7eebcefec434b986b13fa5d7768c1e89a793c41be58f977195.json")).unwrap()];
    for input in inputs {
        println!("--- input ---");
        let store = MemoryBlockstore::new();
        let actor_codes = get_test_code_cid_map().unwrap();
        let (pre_state_root, post_state_root, _) =
            load_evm_contract_input(&store, actor_codes, &input)
                .expect("failed to load evm contract input");
        let expected_evm_actors_slots =
            get_evm_actors_slots("expected", post_state_root, &store).unwrap();
        let message = to_message(&input);

        let vm = test_vm::VM::new(&store);
        vm.state_root.replace(pre_state_root);

        if input.create_contract() {
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

            assert_eq!(return_value, input.return_value.to_vec());
        }
        // compare slot
        let actual_evm_actors_slots =
            get_evm_actors_slots("actual", vm.state_root.borrow().clone(), &store).unwrap();
        for (eth_addr, expected_evm_actor_slots) in expected_evm_actors_slots {
            let actual_evm_actor_slots = actual_evm_actors_slots
                .get(&eth_addr)
                .expect(&*format!("vm actor state slot empty: {:?}", eth_addr));
            for (k, expected_slot_value) in expected_evm_actor_slots {
                let actual_slot_value = actual_evm_actor_slots
                    .get(&k)
                    .expect(&*format!("vm actor state slot key empty: {:?}", eth_addr))
                    .clone();
                assert_eq!(actual_slot_value, expected_slot_value);
            }
        }
    }
}

#[async_std::test]
async fn compare_fvm_output() {
    let bs = MemoryBlockstore::new();

    let file = File::open("blockstores/blockstore.car").await.unwrap();
    let reader = BufReader::new(file);

    let cids = load_car(&bs, reader).await.unwrap();
    let actual_post_root = cids[0];
    let expected_post_root = cids[1];

    if let Ok(Some(StateRoot { version, info, actors })) = bs.get_cbor(&actual_post_root) {
        let _ = get_evm_actors_slots("actual", actors, &bs);
    }

    if let Ok(Some(StateRoot { version, info, actors })) = bs.get_cbor(&expected_post_root) {
        let _ = get_evm_actors_slots("expected", actors, &bs);
    }
}

#[test]
fn test() {
    let arr = [1, 2, 3, 4, 5];
    println!("arr slice: {:?}", &arr[..5 - 2]);
    println!("arr slice: {:?}", &arr[0]);
}
