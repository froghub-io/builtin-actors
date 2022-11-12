mod util;

use std::{env, fs};
use fvm_shared::address::Address;
use test_tvx::{EVM_ACTOR_CODE_ID, EvmContractInput, is_create, string_to_bytes, string_to_U256};

#[test]
fn exec_contract_construction_and_invocation() {
    let input_evm_contract_data = env::var("INPUT_EVM_CONTRACT_DATA").expect("Please set the environment variable (env: INPUT_EVM_CONTRACT_DATA) ");
    let input_evm_contract_content = fs::read_to_string(input_evm_contract_data).unwrap();
    let input: EvmContractInput = serde_json::from_str(&input_evm_contract_content).unwrap();
    //todo actor_id和evm contract address 映射问题
    let contract = Address::new_id(100);
    let mut rt = util::init_construct_and_verify(&input, |rt| {
        rt.actor_code_cids.insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    if !is_create(input.context.to) {
        let input_data = string_to_bytes(input.context.input);
        util::invoke_contract(&mut rt, &input_data);
    }

    let storage = rt.store.load(rt.states.clone());
    for state in input.states {
        for (k, v) in state.partial_storage_after {
            let uk = string_to_U256(k);
            let uv = string_to_U256(v);
            let val = storage.get(&uk).expect("contract state key not exist").clone();
            assert_eq!(uv, val);
        }
    }

    assert_eq!(rt.return_result, input.context.return_result);
}