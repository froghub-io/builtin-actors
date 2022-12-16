use std::cell::RefCell;
use std::collections::HashMap;

use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_init::State as InitState;
use fil_actor_system::State as SystemState;
use fil_actors_runtime::{runtime::EMPTY_ARR_CID, INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR, EAM_ACTOR_ADDR, EAM_ACTOR_ID, AsActorError, ActorError};
use fvm_ipld_blockstore::{Block, Blockstore};
use fvm_ipld_encoding::{tuple::*, Cbor, CborStore, RawBytes, strict_bytes};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::{address::Address, econ::TokenAmount, IPLD_RAW, MethodNum, METHOD_SEND};
use fvm_shared::crypto::hash::SupportedHashes;
use fvm_shared::error::ExitCode;
use fvm_shared::message::Message;
use multihash::{Code, MultihashGeneric};
use fil_actor_evm::interpreter::{StatusCode, U256};
use fil_actor_evm::state::State;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::test_utils::{ACTOR_CODES, EAM_ACTOR_CODE_ID};
use crate::{EvmContractContext, is_create_contract, string_to_big_int, string_to_bytes, string_to_eth_address, U256_to_bytes};
use serde::{Deserialize, Serialize};
use fil_actor_evm::interpreter::system::StateKamt;
use fvm_ipld_kamt::Config as KamtConfig;
use cid::multihash::MultihashDigest;
use fvm_shared::address::Payload;
use num_traits::Zero;
use crate::util::get_code_cid_map;

lazy_static::lazy_static! {
    // The Solidity compiler creates contiguous array item keys.
    // To prevent the tree from going very deep we use extensions,
    // which the Kamt supports and does in all cases.
    //
    // There are maximum 32 levels in the tree with the default bit width of 8.
    // The top few levels will have a higher level of overlap in their hashes.
    // Intuitively these levels should be used for routing, not storing data.
    //
    // The only exception to this is the top level variables in the contract
    // which solidity puts in the first few slots. There having to do extra
    // lookups is burdensome, and they will always be accessed even for arrays
    // because that's where the array length is stored.
    //
    // However, for Solidity, the size of the KV pairs is 2x256, which is
    // comparable to a size of a CID pointer plus extension metadata.
    // We can keep the root small either by force-pushing data down,
    // or by not allowing many KV pairs in a slot.
    //
    // The following values have been set by looking at how the charts evolved
    // with the test contract. They might not be the best for other contracts.
    static ref KAMT_CONFIG: KamtConfig = KamtConfig {
        min_data_depth: 0,
        bit_width: 5,
        max_array_width: 1
    };
}

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

pub fn print_actor_state<BS: Blockstore>(state_root: Cid, store: &BS) {
    println!("--- actor state ---");
    let actors = Hamt::<&BS, Actor, BytesKey, Sha256>::load(&state_root, store).unwrap();
    actors.for_each(|_, v| {
        let state_root = v.head;
        let store = store.clone();
        match store.get_cbor::<State>(&state_root) {
            Ok(res) => {
                match res {
                    Some(state) => {
                        if v.predictable_address.is_some() {
                            let delegated_addr = match v.predictable_address.unwrap().payload() {
                                Payload::Delegated(delegated) if delegated.namespace() == EAM_ACTOR_ID => {
                                    // sanity check
                                    assert_eq!(delegated.subaddress().len(), 20);
                                    Ok(*delegated)
                                }
                                _ => Err(ActorError::assertion_failed(format!(
                                    "EVM actor with delegated address {} created not namespaced to the EAM {}",
                                    v.predictable_address.unwrap(), EAM_ACTOR_ID,
                                ))),
                            }.unwrap();
                            let receiver_eth_addr = {
                                let subaddr: [u8; 20] = delegated_addr.subaddress().try_into().map_err(|_| {
                                    ActorError::assertion_failed(format!(
                                        "expected 20 byte EVM address, found {} bytes",
                                        delegated_addr.subaddress().len()
                                    ))
                                }).unwrap();
                                EthAddress(subaddr)
                            };
                            println!("eth_addr: {:?}", hex::encode(receiver_eth_addr.0));
                        }
                        let bytecode = store
                            .get(&state.bytecode)
                            .context_code(ExitCode::USR_NOT_FOUND, "failed to read bytecode").unwrap()
                            .expect("bytecode not in state tree");
                        println!("bytecode: {:?}", hex::encode(bytecode));
                        let slots = StateKamt::load_with_config(&state.contract_state, store, KAMT_CONFIG.clone())
                            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();
                        slots.for_each(|k, v| {
                                println!("--k: {:?}", hex::encode(U256_to_bytes(k)));
                                println!("--v: {:?}", hex::encode(U256_to_bytes(v)));
                                Ok(())
                            })
                            .unwrap();
                    },
                    None => {}
                }
            },
            Err(_) => {}
        }
        Ok(())
    }).unwrap();
}

pub struct Mock<'bs, BS>
where
    BS: Blockstore,
{
    store: &'bs BS,
    state_root: RefCell<Cid>,
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

    pub fn mock_builtin_actor(&mut self) -> () {
        let map = get_code_cid_map().unwrap();

        // system
        let sys_st = SystemState::new(self.store).unwrap();
        let head_cid = self.store.put_cbor(&sys_st, multihash::Code::Blake2b256).unwrap();
        let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
        self.set_actor(
            SYSTEM_ACTOR_ADDR,
            actor(map.get(&(Type::System as u32)).unwrap().clone(), head_cid, 0, faucet_total, None),
        );

        //init
        let init_st = InitState::new(self.store, "integration-test".to_string()).unwrap();
        let head_cid = self.store.put_cbor(&init_st, multihash::Code::Blake2b256).unwrap();
        let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
        self.set_actor(
            INIT_ACTOR_ADDR,
            actor(map.get(&(Type::Init as u32)).unwrap().clone(), head_cid, 0, faucet_total, None),
        );

        // Ethereum Address Manager
        self.set_actor(
            EAM_ACTOR_ADDR,
            actor(map.get(&(Type::EAM as u32)).unwrap().clone(), EMPTY_ARR_CID, 0, TokenAmount::zero(), None),
        );
    }

    pub fn mock_embryo_address_actor(&mut self, addr: Address, balance: TokenAmount) -> () {
        let map = get_code_cid_map().unwrap();
        let mut id_addr = Address::new_id(0);
        self.mutate_state(INIT_ACTOR_ADDR, |st: &mut InitState| {
            let (addr_id, exist) = st.map_addresses_to_id(self.store, &addr, None).unwrap();
            assert!(!exist);
            id_addr = Address::new_id(addr_id);
        });
        self.set_actor(
            id_addr,
            actor(map.get(&(Type::Embryo as u32)).unwrap().clone(), EMPTY_ARR_CID, 0, balance, Some(addr)),
        );
    }

    pub fn mock_evm_actor(&mut self, addr: Address, balance: TokenAmount) {
        let mut id_addr = Address::new_id(0);
        let robust_address = Address::new_actor(&addr.to_bytes());
        self.mutate_state(INIT_ACTOR_ADDR, |st: &mut InitState| {
            let (addr_id, exist) = st.map_addresses_to_id(self.store, &robust_address, Some(&addr)).unwrap();
            assert!(!exist);
            id_addr = Address::new_id(addr_id);
        });
        self.set_actor(
            id_addr,
            actor(ACTOR_CODES.get(&Type::EVM).cloned().unwrap().clone(), EMPTY_ARR_CID, 0, balance, Some(addr)),
        );
    }

    pub fn hash(&self, hasher: SupportedHashes, data: &[u8]) -> Vec<u8> {
        let hasher = Code::try_from(hasher as u64).unwrap();
        let (_, digest, written) = hasher.digest(data).into_inner();
        Vec::from(&digest[..written as usize])
    }

    pub fn mock_evm_actor_state(&mut self, addr: Address, storage: HashMap<U256, U256>, bytecode: Option<Vec<u8>>) {
        let addr = self.normalize_address(&addr).unwrap();
        let state_root = self.get_actor(addr).unwrap().head;
        let (mut slots, bytecode_cid, bytecode_hash, nonce) = match self.store.get_cbor::<State>(&state_root) {
            Ok(res) => {
                match res {
                    Some(state) => {
                        let slots = StateKamt::load_with_config(&state.contract_state, self.store, KAMT_CONFIG.clone())
                            .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();
                        (slots, Some(state.bytecode), Some(state.bytecode_hash), state.nonce)
                    },
                    None => {
                        let slots = StateKamt::new_with_config(self.store, KAMT_CONFIG.clone());
                        (slots, None, None, 1)
                    }
                }
            },
            Err(_) => {
                let slots = StateKamt::new_with_config(self.store, KAMT_CONFIG.clone());
                (slots, None, None, 1)
            }
        };
        let mut unchanged = true;

        for (key, value) in storage {
            let changed = if value.is_zero() {
                slots.delete(&key).map(|v| v.is_some())
            } else {
                slots.set(key, value).map(|v| v != Some(value))
            }.map_err(|e| StatusCode::InternalError(e.to_string())).unwrap();
            if changed {
                unchanged = false;
            }
        }

        let generate = |bytecode: Vec<u8>| -> (MultihashGeneric<64_usize>, Cid) {
            let code_hash = multihash::Multihash::wrap(
                SupportedHashes::Keccak256 as u64,
                &self.hash(SupportedHashes::Keccak256, &bytecode),
            ).context_code(ExitCode::USR_ILLEGAL_STATE, "failed to hash bytecode with keccak").unwrap();
            let bytecode_cid = self.store
                .put(Code::Blake2b256, &Block::new(IPLD_RAW, bytecode))
                .context_code(ExitCode::USR_ILLEGAL_STATE, "failed to write bytecode").unwrap();
            (code_hash, bytecode_cid)
        };

        let (bytecode_hash, bytecode) = if let Some(bytecode_cid) = bytecode_cid {
            if let Some(bytecode) = bytecode {
                let old_bytecode = self.store
                    .get(&bytecode_cid)
                    .context_code(ExitCode::USR_NOT_FOUND, "failed to read bytecode").unwrap()
                    .expect("bytecode not in state tree");
                if bytecode.eq(&old_bytecode) {
                    (bytecode_hash.unwrap(), bytecode_cid)
                } else {
                    unchanged = false;
                    generate(bytecode)
                }
            } else {
                (bytecode_hash.unwrap(), bytecode_cid)
            }
        } else {
            let bytecode = if let Some(bytecode) = bytecode { unchanged = false; bytecode } else { vec![0u8; 0] };
            generate(bytecode)
        };

        if unchanged {
            return;
        }
        let new_root = self.store
            .put_cbor(
                &State {
                    bytecode,
                    bytecode_hash,
                    contract_state: slots.flush().context_code(
                        ExitCode::USR_ILLEGAL_STATE,
                        "failed to flush contract state",
                    ).unwrap(),
                    nonce,
                },
                Code::Blake2b256,
            )
            .context_code(ExitCode::USR_ILLEGAL_STATE, "failed to write contract state").unwrap();

        let mut a = self.get_actor(addr).unwrap();
        a.head = new_root;
        self.set_actor(addr, a);
    }

    pub fn get_state_root(&self) -> Cid {
        let cid: &Cid = &self.state_root.borrow();
        cid.clone()
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

    pub fn to_message(&self, context: EvmContractContext) -> Message {
        let from = Address::new_delegated(10, &string_to_eth_address(&context.from).0).unwrap();
        let to: Address;
        let method_num: MethodNum;
        let mut params = RawBytes::serialize(ContractParams(vec![0u8; 0])).unwrap();
        if is_create_contract(&context.to) {
            to = Address::new_id(10);
            method_num = fil_actor_eam::Method::Create as u64;
            let params2 = fil_actor_eam::CreateParams {
                initcode: string_to_bytes(&context.input),
                nonce: context.nonce
            };
            params = RawBytes::serialize(params2).unwrap();
        } else {
            to = Address::new_delegated(10, &string_to_eth_address(&context.to).0).unwrap();
            if context.input.len() > 0 {
                params = RawBytes::serialize(ContractParams(string_to_bytes(&context.input))).unwrap();
                method_num = fil_actor_evm::Method::InvokeContract as u64
            } else {
                method_num = METHOD_SEND;
            }
        }
        Message {
            version: 0,
            from,
            to,
            sequence: context.nonce,
            value: TokenAmount::from_atto(string_to_big_int(&context.value.hex)),
            method_num,
            params,
            gas_limit: 9999,
            gas_fee_cap: TokenAmount::from_nano(0),
            gas_premium: TokenAmount::from_nano(0),
        }
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
