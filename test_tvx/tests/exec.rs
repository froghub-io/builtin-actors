use async_std::channel::bounded;
use async_std::io::Cursor;
use async_std::sync::RwLock;
use bytes::Buf;
use fil_actor_eam::EthAddress;
use fil_actor_evm::interpreter::U256;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::{EAM_ACTOR_ADDR, EAM_ACTOR_ID, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR};
use flate2::bufread::GzDecoder;
use flate2::bufread::GzEncoder;
use flate2::Compression;
use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_blockstore::MemoryBlockstore;
use fvm_ipld_car::{load_car, CarHeader};
use fvm_ipld_encoding::{strict_bytes, BytesDe, Cbor, RawBytes};
use fvm_shared::address::Address;
use fvm_shared::econ::TokenAmount;
use fvm_shared::METHOD_SEND;
use num_traits::Zero;
use serde::{Deserialize, Serialize};
use serde_tuple::*;
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use test_tvx::export_test_vector_file;
use test_tvx::mock_single_actors::{print_actor_state, Mock};
use test_tvx::tracing_blockstore::TracingBlockStore;
use test_tvx::{
    compute_address_create, export, is_create_contract, string_to_U256, string_to_bytes,
    string_to_eth_address, EvmContractInput, EvmContractState,
};
use test_vm::util::apply_ok;
use test_vm::FAUCET_ROOT_KEY;

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

#[derive(Serialize_tuple, Deserialize_tuple)]
pub struct CreateParams {
    #[serde(with = "strict_bytes")]
    pub initcode: Vec<u8>,
    pub nonce: u64,
}

impl Cbor for CreateParams {}

#[test]
fn evm_create_test() {
    let from = string_to_eth_address("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54");
    let expected = string_to_eth_address("0xcc3d7ca4a302d196e70760e772ee26d38bd09dca");
    let result = compute_address_create(&EthAddress(from.0), 1);
    assert_eq!(result.0[..], expected.0[..]);
}

#[async_std::test]
async fn mock_single_actor_blockstore() {
    let store = TracingBlockStore::new(MemoryBlockstore::new());
    let mut mock = Mock::new(&store);
    mock.mock_builtin_actor();

    let eth_addr = Address::new_delegated(
        EAM_ACTOR_ID,
        &string_to_eth_address("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54").0,
    )
    .unwrap();
    mock.mock_embryo_address_actor(eth_addr, TokenAmount::zero());

    let (tx, mut rx) = bounded(100);

    let state_root = mock.get_state_root();
    let car_header = CarHeader::new(vec![state_root], 1);
    let buffer: Arc<RwLock<Vec<u8>>> = Default::default();
    let buffer_cloned = buffer.clone();
    let write_task = async_std::task::spawn(async move {
        car_header.write_stream_async(&mut *buffer_cloned.write().await, &mut rx).await.unwrap()
    });

    for cid in (&store).traced.borrow().iter() {
        tx.send((cid.clone(), store.base.get(cid).unwrap().unwrap())).await.unwrap();
    }

    drop(tx);
    write_task.await;

    let car_bytes = buffer.read().await.clone();
    println!("car_bytes: {:?}", car_bytes);

    let mut gz_car_bytes: Vec<u8> = Default::default();
    let mut gz_encoder = GzEncoder::new(car_bytes.reader(), Compression::new(9));
    gz_encoder.read_to_end(&mut gz_car_bytes).unwrap();

    let mut gz_decoder = GzDecoder::new(gz_car_bytes.as_slice());

    let mut car_bytes: Vec<u8> = Default::default();
    gz_decoder.read_to_end(&mut car_bytes).unwrap();

    let car_reader = Cursor::new(car_bytes);
    let test_store = MemoryBlockstore::new();
    load_car(&test_store, car_reader).await.unwrap();

    // An empty built-in actors manifest.
    // let manifest_cid = { store.put_cbor(&Manifest::DUMMY_CODES, Code::Blake2b256).unwrap() };
    // let actors_cid = store.put_cbor(&(1, manifest_cid), Code::Blake2b256).unwrap();

    // let vm = test_vm::VM::new(&store.base);
    let vm = test_vm::VM::new(&test_store);
    vm.state_root.replace(mock.get_state_root());

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

#[async_std::test]
async fn exec_export() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();
    export_test_vector_file(input, Path::new("constract2_test_vector.json").to_path_buf())
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
        let store = MemoryBlockstore::new();
        let mut mock = Mock::new(&store);
        mock.mock_builtin_actor();

        let from =
            Address::new_delegated(10, &string_to_eth_address(&input.context.from).0).unwrap();
        mock.mock_embryo_address_actor(from, TokenAmount::zero());

        for (eth_addr, state) in input.states {
            let eth_addr = string_to_eth_address(&eth_addr);
            if is_create_contract(&input.context.to)
                && eth_addr.eq(&compute_address_create(
                    &string_to_eth_address(&input.context.from),
                    input.context.nonce,
                ))
            {
                continue;
            }
            let to = Address::new_delegated(10, &eth_addr.0).unwrap();
            mock.mock_evm_actor(to, TokenAmount::zero());

            let mut storage = HashMap::<U256, U256>::new();
            for (k, v) in state.partial_storage_before {
                let key = string_to_U256(&k);
                let value = string_to_U256(&v);
                storage.insert(key, value);
            }
            let bytecode = string_to_bytes(&state.code);
            mock.mock_evm_actor_state(to, storage, Some(bytecode));
        }

        let vm = test_vm::VM::new(&store);
        vm.state_root.replace(mock.get_state_root());
        let params = string_to_bytes(&input.context.input);

        if is_create_contract(&input.context.to) {
            let create_result = vm
                .apply_message(
                    from,
                    EAM_ACTOR_ADDR,
                    TokenAmount::zero(),
                    fil_actor_eam::Method::Create as u64,
                    CreateParams { initcode: params, nonce: input.context.nonce },
                )
                .unwrap();

            assert!(
                create_result.code.is_success(),
                "failed to create the new actor {}",
                create_result.message
            );

            // let create_return: fil_actor_eam::CreateReturn =
            //     create_result.ret.deserialize().expect("failed to decode results");

            // println!("create_return: {:?}", create_return);
        } else {
            let to =
                Address::new_delegated(10, &string_to_eth_address(&input.context.to).0).unwrap();
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

            assert_eq!(result, input.context.return_result);
        }
    }
}

#[test]
fn exec_contract_1() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract1.json")).unwrap();
    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_builtin_actor();

    let from = Address::new_delegated(
        10,
        &string_to_eth_address("0x443c0c6F6Cb301B49eE5E9Be07B867378e73Fb54").0,
    )
    .unwrap();
    mock.mock_embryo_address_actor(from, TokenAmount::zero());

    let vm = test_vm::VM::new(&store);
    vm.state_root.replace(mock.get_state_root());

    let params = string_to_bytes(&input.context.input);
    let create_result = vm
        .apply_message(
            from,
            EAM_ACTOR_ADDR,
            TokenAmount::zero(),
            fil_actor_eam::Method::Create as u64,
            CreateParams { initcode: params, nonce: input.context.nonce },
        )
        .unwrap();

    assert!(
        create_result.code.is_success(),
        "failed to create the new actor {}",
        create_result.message
    );

    let create_return: fil_actor_eam::CreateReturn =
        create_result.ret.deserialize().expect("failed to decode results");

    println!("create_return: {:?}", create_return);

    print_actor_state(vm.state_root.borrow().clone(), &store);
}

#[test]
fn exec_contract_2() {
    let input: EvmContractInput =
        serde_json::from_str(include_str!("contracts/contract2.json")).unwrap();

    let store = MemoryBlockstore::new();
    let mut mock = Mock::new(&store);
    mock.mock_builtin_actor();

    let from = Address::new_delegated(10, &string_to_eth_address(&input.context.from).0).unwrap();
    mock.mock_embryo_address_actor(from, TokenAmount::zero());

    let to = Address::new_delegated(10, &string_to_eth_address(&input.context.to).0).unwrap();
    mock.mock_evm_actor(to, TokenAmount::zero());
    let evm_state: EvmContractState =
        input.states.get("0x3471ff6afe294b8cf742dbeababe1476759297f0").unwrap().clone();
    let mut storage = HashMap::<U256, U256>::new();
    for (k, v) in evm_state.partial_storage_before {
        let key = string_to_U256(&k);
        let value = string_to_U256(&v);
        storage.insert(key, value);
    }
    let bytecode = string_to_bytes(&evm_state.code);
    mock.mock_evm_actor_state(to, storage, Some(bytecode));

    let vm = test_vm::VM::new(&store);
    vm.state_root.replace(mock.get_state_root());

    println!("pre_state_root: {:?}", vm.state_root.borrow());

    let params = string_to_bytes(&input.context.input);
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

    println!("return: {:?}", result);
    assert_eq!(result, input.context.return_result);

    println!("post_state_root: {:?}", vm.state_root.borrow());

    print_actor_state(vm.state_root.borrow().clone(), &store);
}
