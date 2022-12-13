use std::cell::RefCell;

use cid::Cid;
use fil_actor_eam::EthAddress;
use fil_actor_init::State as InitState;
use fil_actor_system::State as SystemState;
use fil_actors_runtime::{
    test_utils::{INIT_ACTOR_CODE_ID, SYSTEM_ACTOR_CODE_ID},
    INIT_ACTOR_ADDR, SYSTEM_ACTOR_ADDR,
};
use fvm_ipld_blockstore::{Blockstore, MemoryBlockstore};
use fvm_ipld_encoding::{tuple::*, CborStore};
use fvm_ipld_hamt::{BytesKey, Hamt, Sha256};
use fvm_shared::{address::Address, econ::TokenAmount};

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

    pub fn set_actor(&mut self, actor_addr: Address, actor: Actor) -> () {
        let mut actors =
            Hamt::<&BS, Actor, BytesKey, Sha256>::load(&self.state_root.borrow(), self.store)
                .unwrap();
        actors.set(actor_addr.to_bytes().into(), actor).unwrap();
        self.state_root.replace(actors.flush().unwrap());
    }
}

// pub fn mock_eth_address_actor<BS: Blockstore>(
//     state_root: Cid,
//     store: &BS,
//     eth_addr: EthAddress,
//     balance: TokenAmount,
// ) -> Cid {
//     let addr = Address::new_delegated(10, &eth_addr.0)
// }
