use std::collections::BTreeMap;

use anyhow::{anyhow, Context};
use async_std::task::block_on;
use fvm_ipld_car::load_car_unchecked;
use fvm_ipld_encoding::CborStore;
use fvm_shared::version::NetworkVersion;
use num_traits::FromPrimitive;

use crate::*;
use fil_actors_runtime::runtime::builtins::Type;

pub fn get_code_cid_map() -> anyhow::Result<BTreeMap<Type, Cid>> {
    let bs = MemoryBlockstore::new();
    let actor_v10_bundle = (NetworkVersion::V18, actors_v10::BUNDLE_CAR);
    let roots = block_on(async { load_car_unchecked(&bs, actor_v10_bundle.1).await.unwrap() });
    assert_eq!(roots.len(), 1);

    let manifest_cid = roots[0];
    let (_, builtin_actors_cid): (u32, Cid) =
        bs.get_cbor(&manifest_cid)?.context("failed to load actor manifest")?;

    let vec: Vec<(String, Cid)> = match bs.get_cbor(&builtin_actors_cid)? {
        Some(vec) => vec,
        None => {
            return Err(anyhow!("cannot find manifest root cid {}", manifest_cid));
        }
    };

    let mut by_id: BTreeMap<Type, Cid> = BTreeMap::new();
    for ((_, code_cid), id) in vec.into_iter().zip(1u32..) {
        let actor_type = Type::from_u32(id).unwrap();
        by_id.insert(actor_type, code_cid);
    }
    Ok(by_id)
}

#[test]
fn test_get_code_cid_map() {
    let map = get_code_cid_map().unwrap();
    println!("{:?}", map.get(&Type::Init).unwrap());
}
