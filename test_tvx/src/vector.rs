use cid::Cid;
use fvm_shared::{clock::ChainEpoch, randomness::Randomness, receipt::Receipt};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Deserialize, Clone)]
pub struct Selector {
    #[serde(default)]
    pub chaos_actor: Option<String>,
    #[serde(default)]
    pub min_protocol_version: Option<String>,
    #[serde(default, rename = "requires:consensus_fault_extern")]
    pub consensus_fault: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MetaData {
    pub id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub comment: String,
    pub gen: Vec<GenerationData>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct GenerationData {
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub version: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StateTreeVector {
    #[serde(with = "super::cidjson")]
    pub root_cid: Cid,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Variant {
    pub id: String,
    pub epoch: ChainEpoch,
    pub nv: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PreConditions {
    pub state_tree: StateTreeVector,
    #[serde(default)]
    pub basefee: Option<u128>,
    #[serde(default)]
    pub circ_supply: Option<u128>,
    #[serde(default)]
    pub variants: Vec<Variant>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PostConditions {
    pub state_tree: StateTreeVector,
    #[serde(with = "message_receipt_vec")]
    pub receipts: Vec<Receipt>,
    #[serde(default, with = "super::cidjson::vec")]
    pub receipts_roots: Vec<Cid>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ApplyMessage {
    #[serde(with = "base64_bytes")]
    pub bytes: Vec<u8>,
    #[serde(default)]
    pub epoch_offset: Option<ChainEpoch>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TestVector {
    pub class: String,
    pub selector: Option<Selector>,
    #[serde(rename = "_meta")]
    pub meta: Option<MetaData>,

    #[serde(with = "base64_bytes")]
    pub car: Vec<u8>,
    pub preconditions: PreConditions,
    pub apply_messages: Vec<ApplyMessage>,
    pub postconditions: PostConditions,

    #[serde(default)]
    pub randomness: Randomness,
}

mod base64_bytes {
    use std::borrow::Cow;

    use serde::de;

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Cow<'de, str> = Deserialize::deserialize(deserializer)?;
        base64::decode(s.as_ref()).map_err(de::Error::custom)
    }
}

mod message_receipt_vec {
    use fvm_ipld_encoding::RawBytes;
    use fvm_shared::error::ExitCode;

    use super::*;

    #[derive(Deserialize)]
    pub struct MessageReceiptVector {
        exit_code: ExitCode,
        #[serde(rename = "return", with = "base64_bytes")]
        return_value: Vec<u8>,
        gas_used: i64,
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Receipt>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Vec<MessageReceiptVector> = Deserialize::deserialize(deserializer)?;
        Ok(s.into_iter()
            .map(|v| Receipt {
                exit_code: v.exit_code,
                return_data: RawBytes::new(v.return_value),
                gas_used: v.gas_used,
                events_root: None,
            })
            .collect())
    }
}
