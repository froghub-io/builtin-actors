use std::cell::RefCell;

use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_init::State as InitState;
use fil_actor_system::State as SystemState;
use fil_actors_runtime::{
    runtime::EMPTY_ARR_CID,
    test_utils::{EMBRYO_ACTOR_CODE_ID, INIT_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID},
    INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_ipld_encoding::{tuple::*, Cbor, CborStore};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::{address::Address, econ::TokenAmount, ActorID};
use multihash::Code;
use fil_actors_runtime::runtime::builtins::Type;
use fil_actors_runtime::test_utils::{ACTOR_CODES, EAM_ACTOR_CODE_ID};

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

    pub fn mock_eth_address_actor(&mut self, addr: Address, balance: TokenAmount) {
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
