use crate::CredentialFormat;
use crate::path::ClaimsPathPointer;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::ops::Deref;

/// Vec wrapper that can only be built with at least one item.
#[derive(Debug, Clone)]
pub struct NonEmptyVec<T>(Vec<T>);

impl<T> NonEmptyVec<T> {
    pub fn try_new(values: Vec<T>, empty_error: &'static str) -> Result<Self, String> {
        if values.is_empty() {
            return Err(empty_error.to_string());
        }
        Ok(Self(values))
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T> Deref for NonEmptyVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<'a, T> IntoIterator for &'a NonEmptyVec<T> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> Serialize for NonEmptyVec<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T> Deserialize<'de> for NonEmptyVec<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<T>::deserialize(deserializer)?;
        Self::try_new(
            values,
            "dcql_query.credentials must contain at least one credential query",
        )
        .map_err(D::Error::custom)
    }
}

/// Core DCQL object from OpenID4VP.
///
/// It intentionally models only DCQL members. `transaction_data` belongs to the
/// enclosing Authorization Request and is therefore passed separately to the planner.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcqlQuery {
    /// Requested Credential Queries.
    pub credentials: NonEmptyVec<CredentialQuery>,
    /// Optional combinations constraining which credential query ids can be returned together.
    pub credential_sets: Option<Vec<CredentialSetQuery>>,
}

/// One credential request entry.
///
/// The enum is keyed by `format` to keep the query strongly typed per credential format.
/// Unknown formats are retained at parse time so unsupported query parts can be pruned.
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
pub struct CredentialSetQuery {
    /// Alternative required-id combinations.
    pub options: Vec<Vec<String>>,
    /// Whether this set is mandatory.
    #[serde(default = "default_required")]
    pub required: bool,
    /// Optional verifier purpose string/object forwarded as-is.
    pub purpose: Option<Value>,
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
