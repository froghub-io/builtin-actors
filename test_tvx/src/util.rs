use std::cmp::min;

use frc46_token::receiver::types::{FRC46TokenReceived, UniversalReceiverParams, FRC46_TOKEN_TYPE};
use frc46_token::token::types::{BurnParams, TransferFromParams, TransferParams};
use fvm_ipld_bitfield::BitField;
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
    return account
}

pub fn construction(v: &VM, input: EvmContractInput) {

}