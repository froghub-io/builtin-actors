use std::cell::RefCell;
use std::collections::HashMap;

use anyhow::Result;
use cid::Cid;
use fvm_ipld_hamt::Hamt;

use fvm_ipld_blockstore::Blockstore;
use fvm_ipld_encoding::CborStore;
use fvm_shared::error::ExitCode;
use fil_actor_evm::interpreter::U256;
use fil_actor_evm::state::State;
use crate::{AsActorError, U256_to_bytes};

#[derive(Debug, Default, Clone)]
pub struct EvmBlockstore {
    blocks: RefCell<HashMap<Cid, Vec<u8>>>,
}

impl EvmBlockstore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load(&self, states: Vec<Option<Cid>>) -> HashMap<U256, U256> {
        let mut storage: HashMap<U256, U256> = HashMap::new();
        for state in states {
            match state {
                Some(state_root) => {
                    let store = self.clone();
                    let state: State = store
                        .get_cbor(&state_root)
                        .context_code(ExitCode::USR_SERIALIZATION, "failed to decode state").unwrap()
                        .context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();
                    let slots = Hamt::<_, U256, U256>::load(&state.contract_state, store).context_code(ExitCode::USR_ILLEGAL_STATE, "state not in blockstore").unwrap();
                    slots.for_each(|k, v| {
                        storage.insert(k.clone(), v.clone());
                        Ok(())
                    }).unwrap();
                },
                None => {}
            }
        }
        storage
    }
}

impl Blockstore for EvmBlockstore {
    fn has(&self, k: &Cid) -> Result<bool> {
        Ok(self.blocks.borrow().contains_key(k))
    }

    fn get(&self, k: &Cid) -> Result<Option<Vec<u8>>> {
        Ok(self.blocks.borrow().get(k).cloned())
    }

    fn put_keyed(&self, k: &Cid, block: &[u8]) -> Result<()> {
        self.blocks.borrow_mut().insert(*k, block.into());
        Ok(())
    }
}