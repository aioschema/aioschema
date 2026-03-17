//! AIOSchema v0.5.5 type definitions.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::collections::BTreeMap;

// ── Spec constants ────────────────────────────────────────────────────────────

pub const SPEC_VERSION: &str = "0.5.5";

pub const SUPPORTED_VERSIONS: &[&str] = &[
    "0.1", "0.2", "0.3", "0.3.1", "0.4", "0.5", "0.5.1", "0.5.5",
];

/// Fields whose canonical JSON is hashed to produce `core_fingerprint` (§5.6).
/// MUST NOT include `core_fingerprint` itself (bootstrap rule).
pub const CORE_HASH_FIELDS: &[&str] = &[
    "asset_id",
    "schema_version",
    "creation_timestamp",
    "hash_original",
    "creator_id",
];

pub const DEFAULT_HASH_ALG: &str = "sha256";
pub const SOFT_BINDING_THRESHOLD_DEFAULT: u32 = 5;
pub const SOFT_BINDING_THRESHOLD_MAX: u32 = 10;
pub const SIDECAR_SUFFIX: &str = ".aios.json";

// ── HashOriginal ──────────────────────────────────────────────────────────────

/// `hash_original` is either a single prefixed hash string or an array (§5.5).
#[derive(Debug, Clone, PartialEq)]
pub enum HashOriginal {
    Single(String),
    Multi(Vec<String>),
}

impl HashOriginal {
    pub fn as_slice(&self) -> &[String] {
        match self {
            HashOriginal::Single(s) => std::slice::from_ref(s),
            HashOriginal::Multi(v) => v.as_slice(),
        }
    }
}

impl Serialize for HashOriginal {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            HashOriginal::Single(h) => h.serialize(s),
            HashOriginal::Multi(v) => v.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for HashOriginal {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v: Value = Value::deserialize(d)?;
        match v {
            Value::String(s) => Ok(HashOriginal::Single(s)),
            Value::Array(arr) => {
                let strings: Result<Vec<String>, _> = arr
                    .into_iter()
                    .map(|item| match item {
                        Value::String(s) => Ok(s),
                        other => Err(serde::de::Error::custom(format!(
                            "hash_original array element must be a string, got: {other}"
                        ))),
                    })
                    .collect();
                Ok(HashOriginal::Multi(strings?))
            }
            other => Err(serde::de::Error::custom(format!(
                "hash_original must be a string or array, got: {other}"
            ))),
        }
    }
}

// ── Core ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Core {
    pub asset_id:           String,
    pub schema_version:     String,
    pub creation_timestamp: String,
    pub hash_original:      HashOriginal,
    pub creator_id:         String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub core_fingerprint:   Option<String>,

    /// Deprecated alias for `core_fingerprint` (v0.5.5 backward compat).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_schema_block:  Option<String>,

    pub signature:               Option<String>,
    pub manifest_signature:      Option<String>,
    pub anchor_reference:        Option<String>,
    pub previous_version_anchor: Option<String>,
}

impl Core {
    /// Returns `core_fingerprint`, falling back to the deprecated
    /// `hash_schema_block` alias when absent.
    pub fn effective_core_fingerprint(&self) -> Option<&str> {
        self.core_fingerprint
            .as_deref()
            .or(self.hash_schema_block.as_deref())
    }
}

// ── Manifest ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub core:       Core,
    /// BTreeMap gives deterministic key order on serialization.
    pub extensions: BTreeMap<String, Value>,
}

// ── VerificationResult ────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub success:                     bool,
    pub message:                     String,
    pub match_type:                  Option<MatchType>,
    pub signature_verified:          bool,
    pub manifest_signature_verified: bool,
    pub anchor_checked:              bool,
    pub anchor_verified:             bool,
    pub warnings:                    Vec<String>,
}

impl VerificationResult {
    pub(crate) fn fail(msg: impl Into<String>) -> Self {
        VerificationResult {
            success:                     false,
            message:                     msg.into(),
            match_type:                  None,
            signature_verified:          false,
            manifest_signature_verified: false,
            anchor_checked:              false,
            anchor_verified:             false,
            warnings:                    Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchType {
    Hard,
    Soft,
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchType::Hard => write!(f, "hard"),
            MatchType::Soft => write!(f, "soft"),
        }
    }
}

// ── AnchorRecord ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct AnchorRecord {
    pub asset_id:         String,
    pub core_fingerprint: String,
    pub timestamp:        String,
}

// ── VerifyOptions ─────────────────────────────────────────────────────────────

pub struct VerifyOptions<'a> {
    /// Raw Ed25519 public key bytes (32 bytes).
    pub public_key: Option<&'a [u8]>,

    /// Soft binding pHash threshold. Defaults to `SOFT_BINDING_THRESHOLD_DEFAULT`.
    pub soft_binding_threshold: Option<u32>,

    /// Enable Level 3 anchor verification.
    pub verify_anchor: bool,

    /// Anchor resolver callback for Level 3 verification.
    pub resolver: Option<&'a dyn Fn(&str) -> Result<Option<AnchorRecord>, AiosError>>,
}

impl<'a> Default for VerifyOptions<'a> {
    fn default() -> Self {
        VerifyOptions {
            public_key:             None,
            soft_binding_threshold: None,
            verify_anchor:          false,
            resolver:               None,
        }
    }
}

// ── AiosError ─────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AiosError {
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("invalid hash value: {0}")]
    InvalidHash(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("hex decode error: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("anchor error: {0}")]
    Anchor(String),

    #[error("{0}")]
    Other(String),
}
