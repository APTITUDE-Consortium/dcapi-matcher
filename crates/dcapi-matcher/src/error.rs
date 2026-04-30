use crate::models::Ts12DataType;
use alloc::string::String;
use core::error::Error as CoreError;
use dcapi_dcql::ClaimsPathPointer;
use thiserror::Error;

/// TS12-specific request/configuration warnings.
#[derive(Debug, Error)]
pub enum Ts12Error {
    /// Payload is not an object.
    #[error("transaction_data[{index}] payload must be an object")]
    PayloadNotObject { index: usize },
    /// Failed to serialize TS12 metadata.
    #[error("failed to serialize ts12 metadata for transaction_data[{index}]: {source}")]
    MetadataSerialization {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
}

/// TS12 metadata shape errors (credential package warnings).
#[derive(Debug, Error)]
pub enum Ts12MetadataError {
    /// Missing metadata entry for a required transaction data type.
    #[error("credential {credential_id} ts12 metadata missing entry for {data_type:?}")]
    MissingMetadata {
        credential_id: String,
        data_type: Ts12DataType,
    },
    /// Transaction data metadata does not match the requested type/subtype.
    #[error(
        "credential {credential_id} ts12 metadata type mismatch (expected {expected:?}, got {actual:?})"
    )]
    MetadataTypeMismatch {
        credential_id: String,
        expected: Ts12DataType,
        actual: Ts12DataType,
    },
    /// Missing claim metadata for a payload path.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} missing claim metadata for path {path:?}"
    )]
    MissingClaimMetadata {
        credential_id: String,
        data_type: Ts12DataType,
        path: ClaimsPathPointer,
    },
    /// Missing localized label for a claim.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} missing label for locale {locale} at path {path:?}"
    )]
    MissingClaimLabel {
        credential_id: String,
        data_type: Ts12DataType,
        locale: String,
        path: ClaimsPathPointer,
    },
    /// Empty localized label for a claim.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} empty label for locale {locale} at path {path:?}"
    )]
    EmptyClaimLabel {
        credential_id: String,
        data_type: Ts12DataType,
        locale: String,
        path: ClaimsPathPointer,
    },
    /// UI labels catalogue missing a required key.
    #[error("credential {credential_id} ts12 metadata for {data_type:?} ui_labels missing {label}")]
    MissingUiLabels {
        credential_id: String,
        data_type: Ts12DataType,
        label: &'static str,
    },
    /// UI labels catalogue missing a localized value for a required key.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} ui_labels missing localized {label} for locale {locale}"
    )]
    MissingLocalizedUiLabel {
        credential_id: String,
        data_type: Ts12DataType,
        label: &'static str,
        locale: String,
    },
    /// Preferred locales are required for TS12 display.
    #[error(
        "credential {credential_id} ts12 metadata for {data_type:?} requires preferred locales"
    )]
    MissingPreferredLocales {
        credential_id: String,
        data_type: Ts12DataType,
    },
}

/// Transaction-data decoding warnings (request-level warnings).
#[derive(Debug, Error)]
pub enum TransactionDataDecodeError {
    /// Base64url decoding failed.
    #[error("transaction_data[{index}] base64url decode failed: {source}")]
    Base64 {
        index: usize,
        #[source]
        source: base64::DecodeError,
    },
    /// JSON decoding failed.
    #[error("transaction_data[{index}] invalid json: {source}")]
    Json {
        index: usize,
        #[source]
        source: serde_json::Error,
    },
    /// Missing transaction data type.
    #[error("transaction_data[{index}] type must be non-empty")]
    MissingType { index: usize },
    /// Missing credential ids.
    #[error("transaction_data[{index}] credential_ids must be non-empty")]
    MissingCredentialIds { index: usize },
}

/// Request data decoding error.
#[derive(Debug, Error)]
pub enum RequestDataError {
    /// Failed to decode request data JSON.
    #[error("request data is not valid json")]
    Json {
        #[source]
        source: serde_json::Error,
    },
}

/// OpenID4VP request errors.
#[derive(Debug, Error)]
pub enum OpenId4VpError {
    /// Request JSON is invalid.
    #[error("openid4vp request is not valid json")]
    Json {
        #[source]
        source: serde_json::Error,
    },
    /// Signed request parsing is not supported.
    #[error("signed openid4vp payload parsing is not supported for {protocol}")]
    SignedPayloadNotSupported {
        protocol: String,
        #[source]
        source: serde_json::Error,
    },
    /// Signed request is malformed.
    #[error("signed openid4vp request is malformed for {protocol}")]
    SignedRequestMalformed { protocol: String },
    /// Signed request could not be verified.
    #[error("signed openid4vp request could not be verified for {protocol}")]
    SignedRequestUnverified { protocol: String },
    /// Signed request missing expected_origins.
    #[error("signed openid4vp request missing expected_origins for {protocol}")]
    ExpectedOriginsMissing { protocol: String },
    /// Signed request missing calling origin.
    #[error("signed openid4vp request missing calling origin for {protocol}")]
    OriginMissing { protocol: String },
    /// Signed request origin mismatch.
    #[error("signed openid4vp request origin mismatch for {protocol}: {origin}")]
    OriginMismatch { protocol: String, origin: String },
}

/// Credential package decoding errors.
#[derive(Debug, Error)]
pub enum CredentialPackageError {
    /// JSON decoding failed.
    #[error("credential package JSON decode failed")]
    JsonDecode {
        #[source]
        source: serde_json::Error,
    },
    /// Reading package bytes failed.
    #[cfg(feature = "std")]
    #[error("credential package read failed")]
    Read {
        #[source]
        source: std::io::Error,
    },
}

/// Error type returned by the matcher framework.
#[derive(Debug, Error)]
pub enum MatcherError {
    /// Request payload is not valid JSON.
    #[error("invalid request json")]
    InvalidRequestJson(#[from] serde_json::Error),
    /// Protocol request uses a malformed `data` payload.
    #[error("invalid request data")]
    InvalidRequestData(#[from] RequestDataError),
    /// OpenID4VP request structure is invalid.
    #[error("invalid openid4vp request")]
    InvalidOpenId4Vp(#[from] OpenId4VpError),
    /// Base64url decoding failed.
    #[error("invalid base64url data")]
    InvalidBase64(#[from] base64::DecodeError),
    /// DCQL planning failed.
    #[error("dcql planning error")]
    Dcql(#[from] dcapi_dcql::PlanError),
    /// Credential package decoding failed.
    #[error("credential package decode error")]
    CredentialPackageDecode(#[from] CredentialPackageError),
    /// Failed to serialize response metadata.
    #[error("response metadata serialization failed")]
    MetadataSerialization {
        #[source]
        source: serde_json::Error,
    },
}

/// Format an error and all of its sources into a single string.
pub fn format_error_chain(err: &dyn CoreError) -> String {
    let mut out = err.to_string();
    let mut current = err.source();
    while let Some(source) = current {
        out.push_str(": ");
        out.push_str(&source.to_string());
        current = source.source();
    }
    out
}
