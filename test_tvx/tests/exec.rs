use cid::Cid;
use evm::interpreter::U256;
use fil_actor_evm as evm;
use fil_actors_runtime::ActorError;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::RawBytes;
use fvm_shared::address::Address;
use test_tvx::EVM_ACTOR_CODE_ID;

mod util;

#[test]
fn exec_contract_construction_and_invocation() {
    let bytecode = hex::decode(include_str!("contracts/simplecoin.hex")).unwrap();
    let contract = Address::new_id(100);

    let mut rt = util::init_construct_and_verify(bytecode, |rt| {
        rt.actor_code_cids.insert(contract, *EVM_ACTOR_CODE_ID);
        rt.set_origin(contract);
    });

    // invoke contract -- getBalance
    // first we invoke without specifying an address, so it would be the system actor and have
    // a balance of 0

    let mut solidity_params = vec![];
    solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // caller id address in U256 form
    let mut arg0 = vec![0u8; 32];
    solidity_params.append(&mut arg0);

    let result = util::invoke_contract(&mut rt, &solidity_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0));

    // invoke contract -- getBalance
    // now we invoke with the owner address, which should have a balance of 10k
    let mut solidity_params = vec![];
    solidity_params.append(&mut hex::decode("f8b2cb4f").unwrap()); // function selector
    // caller id address in U256 form
    let mut arg0 = vec![0u8; 32];
    arg0[12] = 0xff; // it's an ID address, so we enable the flag
    arg0[31] = 100; // the owner address
    solidity_params.append(&mut arg0);

    let result = util::invoke_contract(&mut rt, &solidity_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(10000));
}