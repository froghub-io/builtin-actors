use std::cell::RefCell;
use std::collections::HashMap;

use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_init::State as InitState;
use fil_actor_system::State as SystemState;
use fil_actors_runtime::{runtime::EMPTY_ARR_CID, test_utils::{EMBRYO_ACTOR_CODE_ID, INIT_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID}, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR, AsActorError, cbor};
use fvm_ipld_blockstore::{Block, Blockstore, MemoryBlockstore};
use fvm_ipld_encoding::{tuple::*, Cbor, CborStore, RawBytes};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::{address::Address, econ::TokenAmount, ActorID, IPLD_RAW, MethodNum, METHOD_SEND};
use fvm_shared::error::ExitCode;
use fvm_shared::message::Message;
use multihash::Code;
use fil_actor_evm::interpreter::{StatusCode, U256};
use fil_actor_evm::interpreter::system::StorageStatus;
use fil_actor_evm::state::State;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::test_utils::{ACTOR_CODES, EAM_ACTOR_CODE_ID};
use crate::{EvmContractContext, EvmContractState, string_to_big_int, string_to_bytes, string_to_ETHAddress, string_to_U256, U256_to_bytes};
use serde::{Deserialize, Serialize};

#[derive(Serialize_tuple, Deserialize_tuple, Clone, PartialEq, Eq, Debug)]
pub struct Actor {
    pub code: Cid,
    pub head: Cid,
    pub nonce: u64,
    pub balance: TokenAmount,
    pub predictable_address: Option<Address>,
}

pub fn actor(
    code: Cid,
    head: Cid,
    nonce: u64,
    balance: TokenAmount,
    predictable_address: Option<Address>,
) -> Actor {
    Actor { code, head, nonce, balance, predictable_address }
}

pub struct Mock<'bs, BS>
where
    BS: Blockstore,
{
    pub store: &'bs BS,
    pub state_root: RefCell<Cid>,
}

impl<'bs, BS> Mock<'bs, BS>
where
    BS: Blockstore,
{
    pub fn new(store: &'bs BS) -> Self {
        let mut actors = Hamt::<&BS, Actor, BytesKey, Sha256>::new(&store);
        let state_root = actors.flush().unwrap();
        Self { store, state_root: RefCell::new(state_root) }
    }

    pub fn mock_system_actor(&mut self) -> () {
        let sys_st = SystemState::new(self.store).unwrap();
        let head_cid = self.store.put_cbor(&sys_st, multihash::Code::Blake2b256).unwrap();
        let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
        self.set_actor(
            SYSTEM_ACTOR_ADDR,
            actor(*SYSTEM_ACTOR_CODE_ID, head_cid, 0, faucet_total, None),
        );
    }

    pub fn mock_init_actor(&mut self) -> () {
        let init_st = InitState::new(self.store, "integration-test".to_string()).unwrap();
        let head_cid = self.store.put_cbor(&init_st, multihash::Code::Blake2b256).unwrap();
        let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
        self.set_actor(
            INIT_ACTOR_ADDR,
            actor(*INIT_ACTOR_CODE_ID, head_cid, 0, faucet_total, None),
        );
    }

    pub fn mock_embryo_address_actor(&mut self, addr: Address, balance: TokenAmount) -> () {
        let mut id_addr = Address::new_id(0);
        self.mutate_state(INIT_ACTOR_ADDR, |st: &mut InitState| {
            let addr_id = st.map_address_to_new_id(self.store, &addr).unwrap();
            id_addr = Address::new_id(addr_id);
        });
        self.set_actor(
            id_addr,
            actor(*EMBRYO_ACTOR_CODE_ID, EMPTY_ARR_CID, 0, balance, Some(addr)),
        );
    }

    pub fn mock_evm_actor(&mut self, addr: Address, balance: TokenAmount) {
        let mut id_addr = Address::new_id(0);
        let robust_address = Address::new_actor(&addr.to_bytes());
        self.mutate_state(INIT_ACTOR_ADDR, |st: &mut InitState| {
            let addr_id = st.map_address_to_f4(self.store, &robust_address, &addr).unwrap();
            id_addr = Address::new_id(addr_id);
        });
        self.set_actor(
            id_addr,
            actor(ACTOR_CODES.get(&Type::EVM).cloned().unwrap(), EMPTY_ARR_CID, 0, balance, Some(addr)),
        );
    }

    pub fn mock_init_evm_actor_state(&mut self, addr: Address, storage: HashMap<U256, U256>, bytecode: Vec<u8>) {
        let store  = self.store.clone();
        let mut slots = Hamt::<_, U256, U256>::new(store);
        for (key, value) in storage{
            let mut key_bytes = [0u8; 32];
            key.to_big_endian(&mut key_bytes);
            slots.set(key, value).map_err(|e| StatusCode::InternalError(e.to_string())).unwrap();
        }
        let bytecode_cid = self.store
            .put(Code::Blake2b256, &Block::new(IPLD_RAW, bytecode))
            .context_code(ExitCode::USR_ILLEGAL_STATE, "failed to write bytecode").unwrap();

        let new_root = self.store
            .put_cbor(
                &State {
                    bytecode: bytecode_cid,
                    contract_state: slots.flush().context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        "failed to flush contract state",
                    ).unwrap(),
                    nonce: 1,
                },
                Code::Blake2b256,
            )
            .context_code(ExitCode::USR_ILLEGAL_STATE, "failed to write contract state").unwrap();

        let addr = self.normalize_address(&addr).unwrap();
        let mut a = self.get_actor(addr).unwrap();
        a.head = new_root;
        self.set_actor(addr, a);
    }

    pub fn modify_evm_actor_state(&mut self, addr: Address, storage: HashMap<U256, U256>) {
        let addr = self.normalize_address(&addr).unwrap();
        let state_root = self.get_actor(addr).unwrap().head;
        let state: State = self.store
            .get_cbor(&state_root)
            .context_code(ExitCode::USR_SERIALIZATION, "failed to decode state").unwrap()
            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();

        let mut slots = Hamt::<_, U256, U256>::load(&state.contract_state, self.store)
            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();

        let mut unchanged = true;
        for (key, value) in storage {
            let mut key_bytes = [0u8; 32];
            key.to_big_endian(&mut key_bytes);

            let prev_value = slots.get(&key).map_err(|e| StatusCode::InternalError(e.to_string())).unwrap().cloned();
            if prev_value == Some(value) {
                continue
            }
            unchanged = false;
            slots.set(key, value).map_err(|e| StatusCode::InternalError(e.to_string())).unwrap();
        }
        if unchanged {
            return;
        }
        let new_root = self.store
            .put_cbor(
                &State {
                    bytecode: state.bytecode,
                    contract_state: slots.flush().context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        "failed to flush contract state",
                    ).unwrap(),
                    nonce: state.nonce,
                },
                Code::Blake2b256,
            )
            .context_code(ExitCode::USR_ILLEGAL_STATE, "failed to write contract state").unwrap();

        let mut a = self.get_actor(addr).unwrap();
        a.head = new_root;
        self.set_actor(addr, a);
    }

    pub fn put_store<S>(&self, obj: &S) -> Cid
    where
        S: serde::ser::Serialize,
    {
        self.store.put_cbor(obj, Code::Blake2b256).unwrap()
    }

    pub fn get_state<C: Cbor>(&self, addr: Address) -> Option<C> {
        let a_opt = self.get_actor(addr);
        if a_opt == None {
            return None;
        };
        let a = a_opt.unwrap();
        self.store.get_cbor::<C>(&a.head).unwrap()
    }

    pub fn set_actor(&mut self, actor_addr: Address, actor: Actor) -> () {
        let mut actors =
            Hamt::<&BS, Actor, BytesKey, Sha256>::load(&self.state_root.borrow(), self.store)
                .unwrap();
        actors.set(actor_addr.to_bytes().into(), actor).unwrap();
        self.state_root.replace(actors.flush().unwrap());
    }

    pub fn get_actor(&self, addr: Address) -> Option<Actor> {
        let actors =
            Hamt::<&BS, Actor, BytesKey, Sha256>::load(&self.state_root.borrow(), self.store)
                .unwrap();
        actors.get(&addr.to_bytes()).unwrap().cloned()
    }

    pub fn normalize_address(&self, addr: &Address) -> Option<Address> {
        let st = self.get_state::<InitState>(INIT_ACTOR_ADDR).unwrap();
        st.resolve_address::<BS>(self.store, addr).unwrap()
    }

    pub fn print_actor_evm_state(&self, addr: Address) {
        let addr = self.normalize_address(&addr).unwrap();
        let state_root = self.get_actor(addr).unwrap().head;
        let store = self.store.clone();
        let state: State = store
            .get_cbor(&state_root)
            .context_code(ExitCode::USR_SERIALIZATION, "failed to decode state")
            .unwrap()
            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore")
            .unwrap();
        let slots = Hamt::<_, U256, U256>::load(&state.contract_state, store)
            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore")
            .unwrap();
        slots
            .for_each(|k, v| {
                println!("--k: {:?}", hex::encode(U256_to_bytes(k.clone())));
                println!("--v: {:?}", hex::encode(U256_to_bytes(v.clone())));
                Ok(())
            })
            .unwrap();

        let bytecode = self.store
            .get(&state.bytecode)
            .context_code(ExitCode::USR_NOT_FOUND, "failed to read bytecode").unwrap()
            .expect("bytecode not in state tree");
        println!("bytecode: {:?}", hex::encode(bytecode));
    }


    pub fn to_message(context: EvmContractContext) -> Option<Message> {
        let from = Address::new_delegated(10, &string_to_ETHAddress(context.from).0).unwrap();
        let mut to: Address;
        let mut method_num: MethodNum;
        let mut params = RawBytes::serialize(ContractParams(vec![0u8; 0])).unwrap();
        if string_to_ETHAddress(String::from("0x00")).eq(&string_to_ETHAddress(context.to.clone())){
            to = Address::new_id(10);
            method_num = fil_actor_eam::Method::Create as u64;
            let params2 = fil_actor_eam::CreateParams {
                initcode: string_to_bytes(context.input),
                nonce: context.nonce
            };
            params = RawBytes::serialize(params2).unwrap();
            return None
        } else {
            to = Address::new_delegated(10, &string_to_ETHAddress(context.to).0).unwrap();
            if context.input.len() > 0 {
                params = RawBytes::serialize(ContractParams(string_to_bytes(context.input))).unwrap();
                method_num = fil_actor_evm::Method::InvokeContract as u64
            } else {
                method_num = METHOD_SEND;
            }
        }
        let msg = Message {
            version: 0,
            from,
            to,
            sequence: context.nonce,
            value: TokenAmount::from_atto(string_to_big_int(context.value.hex)),
            method_num,
            params,
            gas_limit: 9999,
            gas_fee_cap: TokenAmount::from_nano(0),
            gas_premium: TokenAmount::from_nano(0),
        };
        Some(msg)
    }

    pub fn mutate_state<C, F>(&mut self, addr: Address, f: F)
    where
        C: Cbor,
        F: FnOnce(&mut C),
    {
        let mut a = self.get_actor(addr).unwrap();
        let mut st = self.store.get_cbor::<C>(&a.head).unwrap().unwrap();
        f(&mut st);
        a.head = self.store.put_cbor(&st, Code::Blake2b256).unwrap();
        self.set_actor(addr, a);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct ContractParams(#[serde(with = "strict_bytes")] pub Vec<u8>);

impl Cbor for ContractParams {}
