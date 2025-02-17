mod asm;

use evm::interpreter::address::EthAddress;
use evm::interpreter::U256;
use evm::EVM_CONTRACT_REVERTED;
use fil_actor_evm as evm;
use fil_actors_runtime::test_utils::*;
use fvm_ipld_encoding::ipld_block::IpldBlock;
use fvm_ipld_encoding::{BytesSer, RawBytes, DAG_CBOR, IPLD_RAW};
use fvm_shared::address::Address as FILAddress;
use fvm_shared::bigint::Zero;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::sys::SendFlags;
use fvm_shared::METHOD_SEND;

mod util;

#[allow(dead_code)]
pub fn call_proxy_contract() -> Vec<u8> {
    let init = "";
    let body = r#"
# this contract takes an address and the call payload and proxies a call to that address
# get call payload size
push1 0x20
calldatasize
sub
# store payload to mem 0x00
push1 0x20
push1 0x00
calldatacopy

# prepare the proxy call
# output offset and size -- 0 in this case, we use returndata
push2 0x00
push1 0x00
# input offset and size
push1 0x20
calldatasize
sub
push1 0x00
# value
push1 0x00
# dest address
push1 0x00
calldataload
# gas
push4 0xffffffff
# do the call
call

# return result through
returndatasize
push1 0x00
push1 0x00
returndatacopy
returndatasize
push1 0x00
return
"#;

    asm::new_contract("call-proxy", init, body).unwrap()
}

#[allow(dead_code)]
pub fn call_proxy_transfer_contract() -> Vec<u8> {
    let init = "";
    let body = r#"
# this contract takes an address and the call payload and proxies a call to that address
# get call payload size
push1 0x20
calldatasize
sub
# store payload to mem 0x00
push1 0x20
push1 0x00
calldatacopy

# prepare the proxy call
# output offset and size -- 0 in this case, we use returndata
push2 0x00
push1 0x00
# input offset and size
push1 0x20
calldatasize
sub
push1 0x00
# value
push1 0x42
# dest address
push1 0x00
calldataload
# gas
push1 0x00
# do the call
call

# return result through
returndatasize
push1 0x00
push1 0x00
returndatacopy
returndatasize
push1 0x00
return
"#;

    asm::new_contract("call-proxy-transfer", init, body).unwrap()
}

#[allow(dead_code)]
pub fn call_proxy_gas2300_contract() -> Vec<u8> {
    let init = "";
    let body = r#"
# this contract takes an address and the call payload and proxies a call to that address
# get call payload size
push1 0x20
calldatasize
sub
# store payload to mem 0x00
push1 0x20
push1 0x00
calldatacopy

# prepare the proxy call
# output offset and size -- 0 in this case, we use returndata
push2 0x00
push1 0x00
# input offset and size
push1 0x20
calldatasize
sub
push1 0x00
# value
push1 0x00
# dest address
push1 0x00
calldataload
# gas
%push(2300)
# do the call
call

# return result through
returndatasize
push1 0x00
push1 0x00
returndatacopy
returndatasize
push1 0x00
return
"#;

    asm::new_contract("call-proxy-gas2300", init, body).unwrap()
}

#[test]
fn test_call() {
    let contract = call_proxy_contract();

    // construct the proxy
    let mut rt = util::construct_and_verify(contract);

    // create a mock target and proxy a call through the proxy
    let target_id = 0x100;
    let target = FILAddress::new_id(target_id);
    let evm_target = EthAddress(hex_literal::hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));
    let f4_target: FILAddress = evm_target.try_into().unwrap();
    rt.actor_code_cids.insert(target, *EVM_ACTOR_CODE_ID);
    rt.add_delegated_address(target, f4_target);

    let evm_target_word = evm_target.as_evm_word();

    // dest + method 0 with no data
    let mut contract_params = vec![0u8; 36];
    evm_target_word.to_big_endian(&mut contract_params[..32]);

    let proxy_call_contract_params = vec![0u8; 4];
    let proxy_call_input_data = make_raw_params(proxy_call_contract_params);

    // expected return data
    let mut return_data = vec![0u8; 32];
    return_data[31] = 0x42;

    rt.expect_gas_available(10_000_000_000u64);
    rt.expect_send_generalized(
        f4_target,
        evm::Method::InvokeContract as u64,
        proxy_call_input_data,
        TokenAmount::zero(),
        Some(0xffffffff),
        SendFlags::empty(),
        RawBytes::serialize(BytesSer(&return_data)).expect("failed to serialize return data"),
        ExitCode::OK,
    );

    let result = util::invoke_contract(&mut rt, &contract_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0x42));
}

// Test that a zero-value call to an actor that doesn't exist doesn't actually create the actor.
#[test]
fn test_empty_call_no_side_effects() {
    let contract = call_proxy_contract();

    // construct the proxy
    let mut rt = util::construct_and_verify(contract);

    // create a mock target and proxy a call through the proxy
    let evm_target = EthAddress(hex_literal::hex!("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"));

    let evm_target_word = evm_target.as_evm_word();

    // dest + method 0 with no data
    let mut contract_params = vec![0u8; 36];
    evm_target_word.to_big_endian(&mut contract_params[..32]);

    // expected return data
    let mut return_data = vec![0u8; 32];
    return_data[31] = 0x42;

    let result = util::invoke_contract(&mut rt, &contract_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0));
    // Expect no calls
    rt.verify();
}

// Make sure we do bare sends when calling accounts/placeholder, and make sure it works.
#[test]
fn test_call_convert_to_send() {
    let contract = call_proxy_contract();

    for code in [*ACCOUNT_ACTOR_CODE_ID, *PLACEHOLDER_ACTOR_CODE_ID] {
        // construct the proxy
        let mut rt = util::construct_and_verify(contract.clone());

        // create a mock actor and proxy a call through the proxy
        let target_id = 0x100;
        let target = FILAddress::new_id(target_id);
        rt.actor_code_cids.insert(target, code);

        let evm_target_word = EthAddress::from_id(target_id).as_evm_word();

        // dest + method 0 with no data
        let mut contract_params = vec![0u8; 36];
        evm_target_word.to_big_endian(&mut contract_params[..32]);

        let proxy_call_contract_params = vec![0u8; 4];
        let proxy_call_input_data = make_raw_params(proxy_call_contract_params);

        // expected return data
        let mut return_data = vec![0u8; 32];
        return_data[31] = 0x42;

        rt.expect_send_generalized(
            target,
            METHOD_SEND,
            proxy_call_input_data,
            TokenAmount::zero(),
            None,
            SendFlags::empty(),
            RawBytes::serialize(BytesSer(&return_data)).expect("failed to serialize return data"),
            ExitCode::OK,
        );

        let result = util::invoke_contract(&mut rt, &contract_params);
        assert_eq!(U256::from_big_endian(&result), U256::from(0x42));
        rt.verify();
    }
}

// Make sure we do bare sends when calling with 0 gas and value
#[test]
fn test_call_convert_to_send2() {
    let contract = call_proxy_transfer_contract();

    // construct the proxy
    let mut rt = util::construct_and_verify(contract);

    // create a mock actor and proxy a call through the proxy
    let target_id = 0x100;
    let target = FILAddress::new_id(target_id);
    rt.actor_code_cids.insert(target, *EVM_ACTOR_CODE_ID);

    let evm_target_word = EthAddress::from_id(target_id).as_evm_word();

    // dest with no data
    let mut contract_params = vec![0u8; 32];
    evm_target_word.to_big_endian(&mut contract_params);

    // we don't expected return data
    let return_data = vec![];

    rt.expect_send(
        target,
        METHOD_SEND,
        None,
        TokenAmount::from_atto(0x42),
        RawBytes::serialize(BytesSer(&return_data)).expect("failed to serialize return data"),
        ExitCode::OK,
    );

    let result = util::invoke_contract(&mut rt, &contract_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0));
    rt.verify();
}

// Make sure we do bare sends when calling with 2300 gas and no value
#[test]
fn test_call_convert_to_send3() {
    let contract = call_proxy_gas2300_contract();

    // construct the proxy
    let mut rt = util::construct_and_verify(contract);

    // create a mock actor and proxy a call through the proxy
    let target_id = 0x100;
    let target = FILAddress::new_id(target_id);
    rt.actor_code_cids.insert(target, *EVM_ACTOR_CODE_ID);

    let evm_target_word = EthAddress::from_id(target_id).as_evm_word();

    // dest with no data
    let mut contract_params = vec![0u8; 32];
    evm_target_word.to_big_endian(&mut contract_params);

    // we don't expected return data
    let return_data = vec![];

    rt.expect_send(
        target,
        METHOD_SEND,
        None,
        TokenAmount::zero(),
        RawBytes::serialize(BytesSer(&return_data)).expect("failed to serialize return data"),
        ExitCode::OK,
    );

    let result = util::invoke_contract(&mut rt, &contract_params);
    assert_eq!(U256::from_big_endian(&result), U256::from(0));
    rt.verify();
}

#[allow(dead_code)]
pub fn filecoin_fallback_contract() -> Vec<u8> {
    hex::decode(include_str!("contracts/FilecoinFallback.hex")).unwrap()
}

#[test]
fn test_reserved_method() {
    let contract = filecoin_fallback_contract();
    let mut rt = util::construct_and_verify(contract);

    let code = rt.call::<evm::EvmContractActor>(0x42, None).unwrap_err().exit_code();
    assert_eq!(ExitCode::USR_UNHANDLED_MESSAGE, code);
}

#[test]
fn test_native_call() {
    let contract = filecoin_fallback_contract();
    let mut rt = util::construct_and_verify(contract);

    // invoke the contract
    rt.expect_validate_caller_any();

    let result = rt.call::<evm::EvmContractActor>(1024, None).unwrap();
    assert_eq!(U256::from_big_endian(&result), U256::from(1024));
}

#[allow(dead_code)]
pub fn callactor_proxy_contract() -> Vec<u8> {
    let init = "";
    let body = r#"
# get call payload size
calldatasize
# store payload to mem 0x00
push1 0x00
push1 0x00
calldatacopy

# prepare the proxy call

# out size
# out off
push1 0x20
push1 0xa0

# in size
# in off
calldatasize
push1 0x00

# dst (callactor precompile)
push20 0xfe00000000000000000000000000000000000003

# gas
push4 0xffffffff

# call_actor must be from delegatecall
delegatecall

# copy result to mem 0x00 (overwrites input data)
returndatasize
push1 0x00
push1 0x00
returndatacopy

# return
returndatasize
push1 0x00
return
"#;

    asm::new_contract("callactor-proxy", init, body).unwrap()
}

#[test]
fn test_callactor_success() {
    // Should work if the called actor succeeds.
    test_callactor_inner(ExitCode::OK)
}

#[test]
fn test_callactor_revert() {
    // Should propegate the return value if the called actor fails.
    test_callactor_inner(EVM_CONTRACT_REVERTED)
}

fn test_callactor_inner(exit_code: ExitCode) {
    let contract = callactor_proxy_contract();

    const CALLACTOR_NUM_PARAMS: usize = 6;

    // construct the proxy
    let mut rt = util::construct_and_verify(contract);
    // create a mock target and proxy a call through the proxy
    let target_id = 0x100;
    let target = FILAddress::new_id(target_id);
    rt.actor_code_cids.insert(target, *EVM_ACTOR_CODE_ID);

    // dest + method 0x42 with no data
    let mut contract_params = Vec::new();

    let method = U256::from(0x42);
    let value = U256::from(0);
    let send_flags = SendFlags::default();
    let codec = U256::from(0);

    let target_bytes = target.to_bytes();
    let target_size = U256::from(target_bytes.len());

    let proxy_call_input_data = vec![];
    let data_size = U256::from(proxy_call_input_data.len());

    contract_params.extend_from_slice(&method.to_bytes());
    contract_params.extend_from_slice(&value.to_bytes());
    contract_params.extend_from_slice(&U256::from(send_flags.bits()).to_bytes());
    contract_params.extend_from_slice(&codec.to_bytes());
    contract_params.extend_from_slice(&data_size.to_bytes());
    contract_params.extend_from_slice(&target_size.to_bytes());
    contract_params.extend_from_slice(&target_bytes);
    contract_params.extend_from_slice(&proxy_call_input_data);

    assert_eq!(
        32 * CALLACTOR_NUM_PARAMS + target_bytes.len() + proxy_call_input_data.len(),
        contract_params.len(),
        "unexpected input length"
    );

    // expected return data
    let mut return_data = vec![0u8; 32];
    return_data[31] = 0x42;

    rt.expect_gas_available(10_000_000_000u64);
    rt.expect_send_generalized(
        target,
        0x42,
        make_raw_params(proxy_call_input_data),
        TokenAmount::zero(),
        Some(0xffffffff),
        send_flags,
        RawBytes::from(return_data),
        exit_code,
    );

    // invoke

    let result = util::invoke_contract(&mut rt, &contract_params);

    // assert return

    #[derive(Debug, PartialEq, Eq)]
    struct CallActorReturn {
        exit_code: ExitCode,
        codec: u64,
        data_offset: u32,
        data_size: u32,
        data: Vec<u8>,
    }

    impl CallActorReturn {
        pub fn read(src: &[u8]) -> Self {
            use fil_actor_evm::interpreter::precompiles::parameter::assert_zero_bytes;
            assert!(src.len() >= 4 * 32, "expected to read at least 4 U256 values, got {:?}", src);

            let bytes = &src[..32];
            let exit_code = {
                assert_zero_bytes::<4>(bytes).unwrap();
                ExitCode::new(u32::from_be_bytes(bytes[28..32].try_into().unwrap()))
            };

            let bytes = &src[32..64];
            let codec = {
                assert_zero_bytes::<8>(bytes).unwrap();
                u64::from_be_bytes(bytes[24..32].try_into().unwrap())
            };

            let bytes = &src[64..96];
            let offset = {
                assert_zero_bytes::<4>(bytes).unwrap();
                u32::from_be_bytes(bytes[28..32].try_into().unwrap())
            };

            let bytes = &src[96..128];
            let size = {
                assert_zero_bytes::<4>(bytes).unwrap();
                u32::from_be_bytes(bytes[28..32].try_into().unwrap())
            };
            let data = Vec::from(&src[offset as usize..(offset + size) as usize]);

            Self { exit_code, codec, data_offset: offset, data_size: size, data }
        }
    }

    let result = CallActorReturn::read(&result);
    let expected = CallActorReturn {
        exit_code,
        codec: DAG_CBOR,
        data_offset: 128,
        data_size: 32,
        data: U256::from(0x42).to_bytes().to_vec(),
    };
    rt.verify();
    assert_eq!(result, expected);
    rt.reset();
}

fn make_raw_params(bytes: Vec<u8>) -> Option<IpldBlock> {
    if bytes.is_empty() {
        return None;
    }

    Some(IpldBlock { codec: IPLD_RAW, data: bytes })
}
