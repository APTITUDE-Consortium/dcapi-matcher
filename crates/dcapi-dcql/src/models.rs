use crate::CredentialFormat;
use crate::path::ClaimsPathPointer;
use serde_json::Value;
use serdev::{Deserialize, Serialize};

/// Core DCQL object from OpenID4VP.
///
/// It intentionally models only DCQL members. `transaction_data` belongs to the
/// enclosing Authorization Request and is therefore passed separately to the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(validate = "validate_dcql_query")]
pub struct DcqlQuery {
    /// Requested Credential Queries.
    pub credentials: Vec<CredentialQuery>,
    /// Optional combinations constraining which credential query ids can be returned together.
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One credential request entry.
///
/// The enum is keyed by `format` to keep the query strongly typed per credential format.
/// Unknown formats are retained at parse time and rejected during validation so deserialization
/// remains forward-compatible.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "format")]
pub enum CredentialQuery {
    /// ISO mdoc credential query.
    #[serde(rename = "mso_mdoc")]
    MsoMdoc {
        #[serde(flatten)]
        common: CredentialQueryCommon,
        /// mdoc-specific meta. Required by spec.
        meta: IsoMdocMeta,
    },
    /// SD-JWT VC credential query.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt {
        #[serde(flatten)]
        common: CredentialQueryCommon,
        /// SD-JWT-specific meta. Required by spec.
        meta: SdJwtMeta,
    },
    /// Unknown format value.
    #[serde(other)]
    Unknown,
}

/// Internal typed wrapper for the parsed `meta` object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Meta {
    IsoMdoc(IsoMdocMeta),
    SdJwtVc(SdJwtMeta),
}

/// `meta` members for `mso_mdoc`.
///
/// Unknown fields are intentionally accepted so extension fields are ignored
/// instead of causing hard parse failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IsoMdocMeta {
    pub doctype_value: String,
}

/// `meta` members for `dc+sd-jwt`.
///
/// Unknown fields are intentionally accepted so extension fields are ignored
/// instead of causing hard parse failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SdJwtMeta {
    pub vct_values: Option<Vec<String>>,
}

/// Format-agnostic Credential Query members.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(validate = "validate_credential_query_common")]
pub struct CredentialQueryCommon {
    pub id: String,
    pub multiple: Option<bool>,
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    pub require_cryptographic_holder_binding: Option<bool>,
    pub claims: Option<Vec<ClaimsQuery>>,
    pub claim_sets: Option<Vec<Vec<String>>>,
}

impl CredentialQuery {
    pub fn common(&self) -> Option<&CredentialQueryCommon> {
        match self {
            Self::MsoMdoc { common, .. } | Self::DcSdJwt { common, .. } => Some(common),
            Self::Unknown => None,
        }
    }

    pub fn id(&self) -> Option<&str> {
        self.common().map(|it| &*it.id)
    }

    /// Normalized format string for supported formats.
    pub fn format(&self) -> CredentialFormat {
        match self {
            Self::MsoMdoc { .. } => CredentialFormat::MsoMdoc,
            Self::DcSdJwt { .. } => CredentialFormat::DcSdJwt,
            Self::Unknown => CredentialFormat::Unknown,
        }
    }

    /// Typed meta object for supported formats.
    pub fn meta(&self) -> Option<Meta> {
        match self {
            Self::MsoMdoc { meta, .. } => Some(Meta::IsoMdoc(meta.clone())),
            Self::DcSdJwt { meta, .. } => Some(Meta::SdJwtVc(meta.clone())),
            Self::Unknown => None,
        }
    }

    /// Trusted authority constraints.
    pub fn trusted_authorities(&self) -> Option<&[TrustedAuthority]> {
        self.common()
            .and_then(|common| common.trusted_authorities.as_deref())
    }

    /// Holder-binding requirement.
    pub fn require_cryptographic_holder_binding(&self) -> Option<bool> {
        self.common()
            .and_then(|common| common.require_cryptographic_holder_binding)
    }

    /// Requested claim constraints.
    pub fn claims(&self) -> Option<&[ClaimsQuery]> {
        self.common().and_then(|common| common.claims.as_deref())
    }

    /// Requested alternatives of claim ids.
    pub fn claim_sets(&self) -> Option<&[Vec<String>]> {
        self.common()
            .and_then(|common| common.claim_sets.as_deref())
    }
}

/// Trusted authority constraint from DCQL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedAuthority {
    /// Trusted authority type identifier.
    pub r#type: String,
    /// Values interpreted according to `type`.
    pub values: Vec<String>,
}

/// Allowed value constraint primitive types for claims.
///
/// OpenID4VP restricts value matching to strings, integers and booleans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ClaimValue {
    String(String),
    Integer(i64),
    Boolean(bool),
}

impl ClaimValue {
    /// Convert into `serde_json::Value` for stores that use JSON internals.
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::String(value) => Value::String(value.clone()),
            Self::Integer(value) => Value::Number((*value).into()),
            Self::Boolean(value) => Value::Bool(*value),
        }
    }
}

/// One requested claim constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimsQuery {
    /// Claim id, required only when `claim_sets` is present.
    pub id: Option<String>,
    /// Claims path pointer selecting claim(s) in the credential payload.
    pub path: ClaimsPathPointer,
    /// Optional accepted values. If present, at least one must match exactly.
    pub values: Option<Vec<ClaimValue>>,
    /// Optional mdoc-specific hint carried through to callers.
    pub intent_to_retain: Option<bool>,
}

impl ClaimsQuery {
    /// Optional claim id.
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
}

/// Credential set constraint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(validate = "validate_credential_set_query")]
pub struct CredentialSetQuery {
    /// Alternative required-id combinations.
    pub options: Vec<Vec<String>>,
    /// Whether this set is mandatory.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Optional verifier purpose string/object forwarded as-is.
    pub purpose: Option<Value>,
}

fn validate_dcql_query(value: &DcqlQuery) -> Result<(), String> {
    if value.credentials.is_empty() {
        return Err(
            "dcql_query.credentials must contain at least one credential query".to_string(),
        );
    }
    Ok(())
}

fn validate_credential_query_common(_value: &CredentialQueryCommon) -> Result<(), String> {
    // Lenient: claim_sets without claims, claims missing id, and empty
    // claim paths are handled gracefully by the planner rather than
    // rejected at parse time.
    Ok(())
}

fn validate_credential_set_query(_value: &CredentialSetQuery) -> Result<(), String> {
    // Lenient: empty options are filtered out by the planner.
    Ok(())
}

/// Default value for `CredentialSetQuery::required`.
pub const fn default_required() -> bool {
    true
}

/// Transaction data type discriminator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TransactionDataType {
    /// Transaction data type identifier.
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Decoded transaction data object used for planning.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionData {
    /// Transaction data type identifier.
    #[serde(rename = "type")]
    pub r#type: String,
    /// Referenced credential query ids that can authorize this transaction.
    pub credential_ids: Vec<String>,
    /// Optional algorithm identifier from OpenID4VP transaction data.
    ///
    /// TS12 uses this value together with `transaction_data_hashes` in KB-JWT processing.
    pub transaction_data_hashes_alg: Option<String>,
    /// Unknown extension fields preserved for forward compatibility.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}
