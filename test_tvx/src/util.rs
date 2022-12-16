use std::cmp::min;

use anyhow::Context;
use async_std::task::block_on;
use frc46_token::receiver::types::{FRC46TokenReceived, UniversalReceiverParams, FRC46_TOKEN_TYPE};
use frc46_token::token::types::{BurnParams, TransferFromParams, TransferParams};
use fvm_ipld_bitfield::BitField;
use fvm_ipld_car::load_car_unchecked;
use fvm_ipld_encoding::{BytesDe, Cbor, RawBytes};
use fvm_shared::address::{Address, BLS_PUB_LEN};
use fvm_shared::crypto::signature::{Signature, SignatureType};
use fvm_shared::deal::DealID;
use fvm_shared::econ::TokenAmount;
use fvm_shared::error::ExitCode;
use fvm_shared::piece::PaddedPieceSize;
use fvm_shared::sector::{PoStProof, RegisteredPoStProof, RegisteredSealProof, SectorNumber};
use fvm_shared::{MethodNum, METHOD_SEND};
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;

use fil_actor_account::Method as AccountMethod;
use fil_actor_cron::Method as CronMethod;
use fil_actor_datacap::{Method as DataCapMethod, MintParams};
use fil_actor_market::ext::verifreg::{
    AllocationRequest, AllocationRequests, ClaimExtensionRequest,
};
use fil_actor_market::{
    ClientDealProposal, DealProposal, Label, Method as MarketMethod, PublishStorageDealsParams,
    PublishStorageDealsReturn,
};
use fil_actor_miner::{
    aggregate_pre_commit_network_fee, max_prove_commit_duration,
    new_deadline_info_from_offset_and_epoch, ChangeBeneficiaryParams, CompactCommD, Deadline,
    DeadlineInfo, DeclareFaultsRecoveredParams, ExpirationExtension2,
    ExtendSectorExpiration2Params, GetBeneficiaryReturn, Method as MinerMethod, PoStPartition,
    PowerPair, PreCommitSectorBatchParams, PreCommitSectorBatchParams2, PreCommitSectorParams,
    ProveCommitAggregateParams, ProveCommitSectorParams, RecoveryDeclaration, SectorClaim,
    SectorOnChainInfo, SectorPreCommitInfo, SectorPreCommitOnChainInfo, State as MinerState,
    SubmitWindowedPoStParams, WithdrawBalanceParams, WithdrawBalanceReturn,
};
use fil_actor_multisig::Method as MultisigMethod;
use fil_actor_multisig::ProposeParams;
use fil_actor_power::{
    CreateMinerParams, CreateMinerReturn, Method as PowerMethod, UpdateClaimedPowerParams,
};
use fil_actor_reward::Method as RewardMethod;
use fil_actor_verifreg::{
    AddVerifierClientParams, AllocationID, ClaimID, ClaimTerm, ExtendClaimTermsParams,
    GetClaimsParams, Method as VerifregMethod, RemoveExpiredAllocationsParams, VerifierParams,
};
use fil_actors_runtime::cbor::deserialize;
use fil_actors_runtime::runtime::policy_constants::{
    MARKET_DEFAULT_ALLOCATION_TERM_BUFFER, MAXIMUM_VERIFIED_ALLOCATION_EXPIRATION,
};

use crate::*;
use fil_actors_runtime::runtime::builtins::Type;

pub fn create_account(v: &VM, eth_addr: EthAddress) -> Address {
    let addr = Address::new_delegated(10, &eth_addr.0).unwrap();
    assert!(v
        .apply_message(
            TEST_FAUCET_ADDR,
            addr,
            TokenAmount::from_atto(42u8),
            METHOD_SEND,
            RawBytes::default(),
        )
        .unwrap()
        .code
        .is_success());
    let account = v.normalize_address(&addr).unwrap();
    return account;
}

fn get_code_cid_map() -> anyhow::Result<HashMap<u32, Cid>> {
    let bs = MemoryBlockstore::new();
    let actor_v10_bundle = (NetworkVersion::V18, actors_v10::BUNDLE_CAR);
    let roots = block_on(async { load_car_unchecked(&bs, actor_v10_bundle.1).await.unwrap() });
    assert_eq!(roots.len(), 1);

    let manifest_cid = roots[0];
    let (_, builtin_actors_cid): (u32, Cid) =
        bs.get_cbor(&manifest_cid)?.context("failed to load actor manifest")?;

    let vec: Vec<(String, Cid)> = match bs.get_cbor(&manifest_cid)? {
        Some(vec) => vec,
        None => {
            return Err(anyhow!("cannot find manifest root cid {}", manifest_cid));
        }
    };

    let mut by_id = HashMap::new();
    for ((name, code_cid), id) in vec.into_iter().zip(1u32..) {
        by_id.insert(id, code_cid);
    }
    Ok(by_id)
}

// #[cfg(any(feature = "testing", test))]
// pub fn get_code_cid_map() -> anyhow::Result<HashMap<u32, Cid>> {
//     let mut by_id = HashMap::new();
//     by_id.insert(Type::System as u32, SYSTEM_ACTOR_CODE_ID);
//     by_id.insert(Type::Init as u32, INIT_ACTOR_CODE_ID);
//     by_id.insert(Type::Cron as u32, CRON_ACTOR_CODE_ID);
//     by_id.insert(Type::Account as u32, ACCOUNT_ACTOR_CODE_ID);
//     by_id.insert(Type::Power as u32, POWER_ACTOR_CODE_ID);
//     by_id.insert(Type::Miner as u32, MINER_ACTOR_CODE_ID);
//     by_id.insert(Type::Market as u32, MARKET_ACTOR_CODE_ID);
//     by_id.insert(Type::PaymentChannel as u32, PAYCH_ACTOR_CODE_ID);
//     by_id.insert(Type::Multisig as u32, MULTISIG_ACTOR_CODE_ID);
//     by_id.insert(Type::Reward as u32, REWARD_ACTOR_CODE_ID);
//     by_id.insert(Type::VerifiedRegistry as u32, VERIFREG_ACTOR_CODE_ID);
//     by_id.insert(Type::DataCap as u32, DATACAP_TOKEN_ACTOR_CODE_ID);
//     by_id.insert(Type::Embryo as u32, EMBRYO_ACTOR_CODE_ID);
//     by_id.insert(Type::EVM as u32, EVM_ACTOR_CODE_ID);
//     by_id.insert(Type::EAM as u32, EAM_ACTOR_CODE_ID);
//     Ok(by_id)
// }

pub fn construction(v: &VM, input: EvmContractInput) {}

#[test]
fn test_get_code_cid_map() {
    let map = get_code_cid_map().unwrap();
    println!("{:?}", map.get(&(Type::Init as u32)).unwrap());
}

#[cfg(all(test, feature = "testing"))]
mod tests {

    use super::*;
    use fil_actors_runtime::runtime::builtins::Type;

    #[test]
    fn get_code_cid_map() {
        // let init_actor_code_cid = get_code_cid_map(Type::Init);
        // println!("{:?}", init_actor_code_cid);
    }
}
