mod util;

use std::{env, fs};
use cid::Cid;
use evm::interpreter::U256;
use fil_actor_evm as evm;
use fil_actors_runtime::ActorError;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use test_tvx::{EVM_ACTOR_CODE_ID, EvmContractInput, is_create, string_to_bytes, string_to_U256, U256_to_bytes};

#[test]
fn exec_contract_construction_and_invocation() {
    let input_evm_contract_data = env::var("INPUT_EVM_CONTRACT_DATA").expect("Please set the environment variable (env: INPUT_EVM_CONTRACT_DATA) ");
    let input_evm_contract_content = fs::read_to_string(input_evm_contract_data).unwrap();
    let input: EvmContractInput = serde_json::from_str(&input_evm_contract_content).unwrap();
    let contract = Address::new_id(100);
    let mut rt = util::init_construct_and_verify(&input, |rt| {
        rt.actor_code_cids.insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    if !is_create(input.context.to) {
        let input_data = string_to_bytes(input.context.input);
        let result = util::invoke_contract(&mut rt, &input_data);
        println!("result: {:?}", hex::encode(result));
    }

    // let mut solidity_params = vec![];
    // solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // // caller id address in U256 form
    // let mut arg0 = vec![0u8; 32];
    // solidity_params.append(&mut arg0);
    //
    // let result = util::invoke_contract(&mut rt, &solidity_params);
    // assert_eq!(U256::from_big_endian(&result), U256::from(0));

    // invoke contract -- getBalance
    // now we invoke with the owner address, which should have a balance of 10k
    // let mut solidity_params = vec![];
    // solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // // caller id address in U256 form
    // let r = hex::decode("443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54").unwrap();
    // let mut arg0 = vec![0u8; 32];
    // arg0[32 - r.len()..32].copy_from_slice(&r);
    // // arg0[12] = 0xff; // it's an ID address, so we enable the flag
    // // arg0[31] = 100; // the owner address
    // solidity_params.append(&mut arg0);
    //
    // let result = util::invoke_contract(&mut rt, &solidity_params);
    // println!("result: {:?}", hex::encode(result));
    // // assert_eq!(U256::from_big_endian(&result), U256::from(10000));
}