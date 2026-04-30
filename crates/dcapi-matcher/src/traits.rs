use crate::config::OpenId4VpConfig;
use crate::diagnostics::LogLevel;
use crate::models::{OpenId4VpSignedEnvelope, PROTOCOL_OPENID4VP};
use crate::ts12::{Ts12PaymentSummary, Ts12TransactionMetadata};
use alloc::borrow::Cow;
use c8str::C8Str;
use dcapi_dcql::{ClaimsPathPointer, CredentialStore};
use serde_json::Value;

/// Context passed when building Credman metadata for one candidate entry.
#[derive(Debug)]
pub struct DcqlSelectionContext<'a> {
    /// Request index in `DcApiRequest.requests`.
    pub request_index: usize,
    /// Alternative index in planned DCQL output.
    pub alternative_index: usize,
    /// DCQL credential query id.
    pub query_id: &'a str,
    /// Claim constraints selected for this query.
    pub selected_claims: &'a [dcapi_dcql::ClaimsQuery],
    /// Transaction data decoded from request.
    pub transaction_data: &'a [dcapi_dcql::TransactionData],
    /// Transaction data indices bound to this query id in the selected alternative.
    pub transaction_data_indices: &'a [usize],
}

impl DcqlSelectionContext<'_> {
    /// Returns a protocol label for metadata serialization.
    pub fn protocol(&self) -> &'static str {
        PROTOCOL_OPENID4VP
    }
}

/// Store contract used by `dcapi-matcher`.
///
/// This extends `dcapi_dcql::CredentialStore` so DCQL matching can be delegated to
/// `dcapi-dcql`. Implementers only need to define how credentials are displayed.
pub trait MatcherStore: CredentialStore {
    /// Credential selection id returned to host.
    fn credential_id<'a>(&'a self, cred: &Self::CredentialRef) -> Cow<'a, C8Str>;

    /// Entry title.
    fn credential_title<'a>(&'a self, cred: &Self::CredentialRef) -> Cow<'a, C8Str>;

    /// Optional icon bytes.
    fn credential_icon<'a>(&'a self, _cred: &Self::CredentialRef) -> Option<&'a [u8]> {
        None
    }

    /// Optional subtitle.
    fn credential_subtitle<'a>(&'a self, _cred: &Self::CredentialRef) -> Option<Cow<'a, C8Str>> {
        None
    }

    /// Optional disclaimer.
    fn credential_disclaimer<'a>(&'a self, _cred: &Self::CredentialRef) -> Option<Cow<'a, C8Str>> {
        None
    }

    /// Optional warning.
    fn credential_warning<'a>(&'a self, _cred: &Self::CredentialRef) -> Option<Cow<'a, C8Str>> {
        None
    }

    /// Optional display field label for a claim path.
    ///
    /// Return `None` when the path includes wildcards (`null` entries).
    fn get_credential_field_label<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        None
    }

    /// Optional display field value for a claim path.
    ///
    /// Return `None` when the path includes wildcards (`null` entries).
    fn get_credential_field_value<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        None
    }

    /// Returns whether this credential is available for a protocol.
    fn supports_protocol(&self, _cred: &Self::CredentialRef, _protocol: &str) -> bool {
        false
    }

    /// Verifies a signed OpenID4VP request.
    ///
    /// Return `true` when the request signatures are verified under a supported trust
    /// framework. Default rejects all signed requests.
    fn verify_openid4vp_signed_request(
        &self,
        _protocol: &str,
        _request: &OpenId4VpSignedEnvelope,
    ) -> bool {
        false
    }

    /// Returns wallet-level OpenID4VP support configuration.
    fn openid4vp_config(&self) -> OpenId4VpConfig {
        OpenId4VpConfig::default()
    }

    /// Locales (RFC5646 identifiers) for UI rendering, in priority order.
    fn locales(&self) -> &[&str];

    /// Logging level for matcher diagnostics. `None` disables logging.
    fn log_level(&self) -> Option<LogLevel> {
        None
    }

    /// Returns resolved TS12 transaction metadata for display and rendering.
    ///
    /// Implementers must resolve any `claims_uri` / `ui_labels_uri` references and apply
    /// `extends` merging rules before returning this metadata. The returned metadata must
    /// already contain the matching `type`/`subtype`. Return `None` when the credential does not
    /// support the provided transaction data type.
    fn ts12_transaction_metadata<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata<'a>> {
        None
    }

    /// Optional payment summary for TS12 flows.
    ///
    /// Return `Some` to render the credential as a payment entry for the given transaction data.
    /// The summary fields must be derived from credential package metadata/payloads and already
    /// localized as needed; the matcher does not inject hardcoded strings.
    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _transaction_data: &dcapi_dcql::TransactionData,
        _payload: &Value,
        _metadata: &Ts12TransactionMetadata<'a>,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary<'a>> {
        None
    }

    /// Optional formatter for TS12 transaction data values.
    ///
    /// This hook lets wallets provide localized or domain-specific value rendering
    /// (for example, translating recurrence frequency codes) without hardcoded strings
    /// in the matcher core. When `None` is returned, the matcher falls back to
    /// a basic string representation of the JSON value.
    fn format_ts12_value<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        _path: &ClaimsPathPointer,
        _value: &Value,
        _locale: &str,
    ) -> Option<Cow<'a, C8Str>> {
        None
    }
}
