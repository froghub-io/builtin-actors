use std::iter;
use fil_actor_evm as evm;
use fil_actors_runtime::{runtime::builtins::Type, EAM_ACTOR_ID, INIT_ACTOR_ADDR};
use fvm_ipld_encoding::{BytesDe, BytesSer, RawBytes};
use fvm_shared::address::Address;
use fil_actor_evm::interpreter::{System};
use fil_actor_evm::interpreter::address::EthAddress;
use fil_actors_runtime::runtime::Runtime;
use test_tvx::{EvmContractInput, INIT_ACTOR_CODE_ID, is_create, MockRuntime, string_to_bytes, string_to_ETHAddress, string_to_U256};

// #[allow(dead_code)]
// pub fn construct_and_verify(initcode: Vec<u8>) -> MockRuntime {
//     init_construct_and_verify(initcode, |_| {})
// }

pub const CONTRACT_ADDRESS: [u8; 20] =
    hex_literal::hex!("FEEDFACECAFEBEEF000000000000000000000000");

pub fn init_construct_and_verify<F: FnOnce(&mut MockRuntime)>(
    input: &EvmContractInput,
    initrt: F,
) -> MockRuntime {
    let mut rt = MockRuntime::default();

    // construct EVM actor
    rt.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);
    rt.expect_validate_caller_type(vec![Type::Init]);
    initrt(&mut rt);

    // first actor created is 0
    rt.add_delegated_address(
        Address::new_id(0),
        Address::new_delegated(EAM_ACTOR_ID, &CONTRACT_ADDRESS).unwrap(),
    );

    if is_create(input.context.to.clone()) {
        let initcode = string_to_bytes(input.context.input.clone());
        let params = evm::ConstructorParams {
            creator: string_to_ETHAddress(input.context.from.clone()),
            initcode: initcode.into(),
        };

        assert!(rt
            .call::<evm::EvmContractActor>(
                evm::Method::Constructor as u64,
                &RawBytes::serialize(params).unwrap(),
            )
            .unwrap()
            .is_empty());
        let system = System::load(&mut rt, true).unwrap();
        let bytecode = system.load_bytecode().unwrap().unwrap();
        let res = hex::encode(bytecode.to_vec());
        rt.set_return_result(res);
    } else {

    }

    rt.verify();

    rt
}

pub fn init_construct_and_verify2<F: FnOnce(&mut MockRuntime)>(
    input: &EvmContractInput,
    initrt: F,
) -> MockRuntime {
    let mut rt = MockRuntime::default();

    // construct EVM actor
    rt.set_caller(*INIT_ACTOR_CODE_ID, INIT_ACTOR_ADDR);
    rt.expect_validate_caller_type(vec![Type::Init]);
    initrt(&mut rt);

    // first actor created is 0
    rt.add_delegated_address(
        Address::new_id(0),
        Address::new_delegated(EAM_ACTOR_ID, &CONTRACT_ADDRESS).unwrap(),
    );

    if is_create(input.context.to.clone()) {
        let mut system = System::create(&mut rt).unwrap();
        for state in input.states.clone() {
            for e in state.partial_storage_before {
                let k = string_to_U256(e.0.clone());
                let v = string_to_U256(e.1.clone());
                system.set_storage(k, Some(v)).unwrap();
            }
        }
        let initcode = string_to_bytes(input.context.input.clone());
        let params = evm::ConstructorParams {
            creator: string_to_ETHAddress(input.context.from.clone()),
            initcode: initcode.into(),
        };

        assert!(rt
            .call::<evm::EvmContractActor>(
                evm::Method::Constructor as u64,
                &RawBytes::serialize(params).unwrap(),
            )
            .unwrap()
            .is_empty());
        // let system = System::load(&mut rt, true).unwrap();
        // let bytecode = system.load_bytecode().unwrap().unwrap();
        // let res = hex::encode(bytecode.to_vec());
        // rt.set_return_result(res);
    } else {
        rt.in_call = true;
        rt.validate_immediate_caller_type(iter::once(&Type::Init)).unwrap();
        let mut system = System::create(&mut rt).unwrap();
        for state in input.states.clone() {
            for e in state.partial_storage_before {
                let k = string_to_U256(e.0.clone());
                let v = string_to_U256(e.1.clone());
                system.set_storage(k, Some(v)).unwrap();
            }
            let contract_bytecode = string_to_bytes(state.code);
            system.set_bytecode(&contract_bytecode).unwrap();
        }
        system.flush().unwrap();
        rt.in_call = false;
    }
    rt.verify();

    rt
}

#[allow(dead_code)]
pub fn invoke_contract(rt: &mut MockRuntime, input_data: &[u8]) {
    rt.expect_validate_caller_any();
    let BytesDe(res) = rt
        .call::<evm::EvmContractActor>(
            evm::Method::InvokeContract as u64,
            &RawBytes::serialize(BytesSer(input_data)).unwrap(),
        )
        .unwrap()
        .deserialize()
        .unwrap();
    rt.set_return_result(hex::encode(res));
}
