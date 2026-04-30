use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use dcapi_dcql::DcqlQuery;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

/// Protocol identifier for OpenID4VP requests in DC API.
pub const PROTOCOL_OPENID4VP: &str = "openid4vp";
/// Protocol identifier for OpenID4VP unsigned requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_UNSIGNED: &str = "openid4vp-v1-unsigned";
/// Protocol identifier for OpenID4VP JWS signed requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_SIGNED: &str = "openid4vp-v1-signed";
/// Protocol identifier for OpenID4VP multi-signed requests in DC API.
pub const PROTOCOL_OPENID4VP_V1_MULTISIGNED: &str = "openid4vp-v1-multisigned";

/// TS12 transaction data type discriminator (OpenID4VP-specific).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Ts12DataType {
    /// Transaction data type identifier.
    #[serde(rename = "type")]
    pub r#type: String,
}

/// Root request envelope passed by DC API to matchers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DcApiRequest {
    /// Requested protocol operations.
    pub requests: Vec<DcApiRequestItem>,
}

/// One protocol request in the DC API request list.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "protocol")]
#[allow(clippy::large_enum_variant)]
pub enum DcApiRequestItem {
    /// OpenID4VP over DC API (unsigned).
    #[serde(rename = "openid4vp-v1-unsigned", alias = "openid4vp")]
    OpenId4VpUnsigned { data: OpenId4VpUnsignedData },
    /// OpenID4VP over DC API (signed JWS compact).
    #[serde(rename = "openid4vp-v1-signed")]
    OpenId4VpSigned { data: OpenId4VpSignedData },
    /// OpenID4VP over DC API (signed JWS JSON serialization).
    #[serde(rename = "openid4vp-v1-multisigned")]
    OpenId4VpMultiSigned { data: OpenId4VpMultiSignedData },
    /// Unknown protocol (ignored by matcher).
    #[serde(other)]
    Unknown,
}

/// OpenID4VP unsigned request data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum OpenId4VpUnsignedData {
    /// Request parameters as JSON object.
    Params(OpenId4VpRequest),
    /// Request parameters encoded as JSON string.
    JsonString(String),
}

/// OpenID4VP signed request data payload (JWS compact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenId4VpSignedData {
    /// JWS compact request object.
    pub request: String,
}

/// OpenID4VP multi-signed request data payload (JWS JSON serialization).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenId4VpMultiSignedData {
    /// Base64url-encoded JWS payload.
    pub payload: String,
    /// Signature list (JWS JSON serialization).
    pub signatures: Vec<OpenId4VpJwsSignature>,
}

/// Parsed and decoded signed OpenID4VP request envelope.
#[derive(Debug, Clone)]
pub struct OpenId4VpSignedEnvelope {
    /// JWS serialization format.
    pub format: OpenId4VpSignedFormat,
    /// Base64url-encoded payload segment.
    pub payload_b64: String,
    /// Decoded payload JSON.
    pub payload: Value,
    /// Signature entries.
    pub signatures: Vec<OpenId4VpSignedSignature>,
}

/// JWS serialization format for signed OpenID4VP requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenId4VpSignedFormat {
    /// JWS Compact Serialization.
    Compact,
    /// JWS JSON Serialization.
    Json,
}

/// Parsed signature entry for a signed OpenID4VP request.
#[derive(Debug, Clone)]
pub struct OpenId4VpSignedSignature {
    /// Base64url-encoded protected header.
    pub protected_b64: String,
    /// Decoded protected header JSON.
    pub protected: Value,
    /// Base64url-encoded signature.
    pub signature_b64: String,
    /// Optional unprotected header.
    pub header: Option<Value>,
}

/// JWS JSON serialization signature entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenId4VpJwsSignature {
    /// Base64url-encoded protected header.
    pub protected: String,
    /// Base64url-encoded signature.
    pub signature: String,
    /// Optional unprotected header.
    #[serde(default)]
    pub header: Option<Value>,
}

/// Raw protocol request payload.
///
/// DC API transports `data` as a string containing JSON in common deployments,
/// but object-valued payloads are also accepted by this matcher.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestData {
    /// JSON document encoded as string.
    JsonString(String),
    /// JSON object/value directly.
    JsonValue(Value),
}

impl RequestData {
    /// Returns the payload as JSON value.
    pub fn to_value(&self) -> Result<Value, serde_json::Error> {
        match self {
            Self::JsonString(raw) => match serde_json::from_str(raw) {
                Ok(value) => Ok(value),
                Err(_) => Ok(Value::String(raw.clone())),
            },
            Self::JsonValue(value) => Ok(value.clone()),
        }
    }
}

/// OpenID4VP request payload.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenId4VpRequest {
    /// Response type parameter.
    #[serde(default, deserialize_with = "deserialize_optional_valid")]
    pub response_type: Option<String>,
    /// Response mode parameter.
    #[serde(default, deserialize_with = "deserialize_optional_valid")]
    pub response_mode: Option<String>,
    /// Nonce parameter for replay protection.
    #[serde(default, deserialize_with = "deserialize_optional_valid")]
    pub nonce: Option<String>,
    /// Verifier client metadata (OpenID4VP).
    pub client_metadata: Option<Value>,
    /// DCQL query request.
    #[serde(default, deserialize_with = "deserialize_optional_valid")]
    pub dcql_query: Option<DcqlQuery>,
    /// Transaction data constraints as defined by OpenID4VP.
    #[serde(default, deserialize_with = "deserialize_transaction_data_inputs")]
    pub transaction_data: Option<Vec<TransactionDataInput>>,
    /// Verifier info object (OpenID4VP).
    pub verifier_info: Option<Value>,
    /// Legacy Presentation Exchange request (ignored by matcher).
    pub presentation_definition: Option<Value>,
    /// Preserved unknown fields.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// One transaction-data request entry, either already decoded or base64url encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionDataInput {
    /// Base64url encoded JSON object.
    Encoded(String),
    /// Decoded JSON object.
    Decoded(Box<dcapi_dcql::TransactionData>),
}

fn deserialize_optional_valid<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    Ok(serde_json::from_value(value).ok())
}

fn deserialize_transaction_data_inputs<'de, D>(
    deserializer: D,
) -> Result<Option<Vec<TransactionDataInput>>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(value) = Option::<Value>::deserialize(deserializer)? else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Ok(None);
    };
    Ok(Some(
        items
            .iter()
            .filter_map(|item| serde_json::from_value(item.clone()).ok())
            .collect(),
    ))
}
