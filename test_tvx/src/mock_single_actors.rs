use cid::Cid;
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

pub fn mock_system_actor<BS: Blockstore>(state_root: Cid, store: &BS) -> Cid {
    let sys_st = SystemState::new(store).unwrap();
    let head_cid = store.put_cbor(&sys_st, multihash::Code::Blake2b256).unwrap();
    let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
    return set_actor(
        state_root,
        store,
        SYSTEM_ACTOR_ADDR,
        actor(*SYSTEM_ACTOR_CODE_ID, head_cid, 0, faucet_total, None),
    );
}

pub fn mock_init_actor<BS: Blockstore>(state_root: Cid, store: &BS) -> Cid {
    let init_st = InitState::new(store, "integration-test".to_string()).unwrap();
    let head_cid = store.put_cbor(&init_st, multihash::Code::Blake2b256).unwrap();
    let faucet_total = TokenAmount::from_whole(1_000_000_000i64);
    return set_actor(
        state_root,
        store,
        INIT_ACTOR_ADDR,
        actor(*INIT_ACTOR_CODE_ID, head_cid, 0, faucet_total, None),
    );
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

pub fn set_actor<BS: Blockstore>(
    state_root: Cid,
    store: &BS,
    actor_addr: Address,
    actor: Actor,
) -> Cid {
    let mut actors = Hamt::<&BS, Actor, BytesKey, Sha256>::load(&state_root, store).unwrap();
    actors.set(actor_addr.to_bytes().into(), actor).unwrap();
    actors.flush().unwrap()
}
