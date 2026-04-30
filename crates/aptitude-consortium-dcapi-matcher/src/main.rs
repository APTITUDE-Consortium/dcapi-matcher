use android_credman::{CredmanRender, get_request_string};
use base64::Engine;
use c8str::{C8Str, C8String, c8, c8format};
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement, PlanOptions,
    TransactionData, TransactionDataType, ValueMatch, path_matches,
};
use dcapi_matcher::diagnostics::info;
use dcapi_matcher::{
    LogLevel, MatcherOptions, MatcherStore, OpenId4VpConfig, Ts12ClaimMetadata, Ts12DataType,
    Ts12LocalizedLabel, Ts12LocalizedValue, Ts12PaymentSummary, Ts12TransactionMetadata,
    Ts12UiLabels, dcapi_matcher, match_dc_api_request,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::borrow::Cow;

#[repr(transparent)]
#[derive(Debug, Clone)]
struct C8StringValue(C8String);

impl core::ops::Deref for C8StringValue {
    type Target = C8Str;

    fn deref(&self) -> &Self::Target {
        self.0.as_c8_str()
    }
}

impl From<C8StringValue> for C8String {
    fn from(value: C8StringValue) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for C8StringValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        C8String::from_string(value)
            .map(C8StringValue)
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Deserialize)]
struct PackageConfig {
    default_id_prefix: Option<String>,
    #[serde(default)]
    openid4vp: OpenId4VpConfig,
    #[serde(default)]
    dcql: PlanOptions,
    log_level: Option<LogLevel>,
    #[serde(default)]
    credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Deserialize, Default)]
struct CredentialConfig {
    #[serde(default)]
    id: Option<C8StringValue>,
    format: String,
    #[serde(default)]
    title: Option<C8StringValue>,
    #[serde(default)]
    subtitle: Option<C8StringValue>,
    #[serde(default)]
    disclaimer: Option<C8StringValue>,
    #[serde(default)]
    warning: Option<C8StringValue>,
    #[serde(default)]
    fields: Vec<CredentialFieldConfig>,
    metadata: Option<Value>,
    icon: Option<IconConfig>,
    #[serde(default)]
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: Option<bool>,
    claims: Option<Value>,
    #[serde(default)]
    transaction_data_types: Vec<Ts12MetadataConfig>,
}

#[derive(Debug, Deserialize)]
struct CredentialFieldConfig {
    path: ClaimsPathPointer,
    display_name: C8StringValue,
    #[serde(default)]
    display_value: Option<C8StringValue>,
}

#[derive(Debug, Deserialize)]
struct Ts12MetadataConfig {
    #[serde(flatten)]
    data_type: Ts12DataType,
    #[serde(default)]
    claims: Vec<Ts12ClaimConfig>,
    #[serde(default)]
    ui_labels: Vec<Ts12UiLabelConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12ClaimConfig {
    path: ClaimsPathPointer,
    #[serde(default)]
    display: Vec<Ts12LocalizedLabelConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12LocalizedLabelConfig {
    locale: String,
    label: C8StringValue,
    #[serde(default)]
    description: Option<C8StringValue>,
}

#[derive(Debug, Deserialize)]
struct Ts12UiLabelConfig {
    key: String,
    #[serde(default)]
    values: Vec<Ts12LocalizedValueConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12LocalizedValueConfig {
    locale: String,
    value: C8StringValue,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum IconConfig {
    Bytes(Vec<u8>),
    Base64(String),
}

#[derive(Debug, Clone)]
struct ResolvedCredential {
    id: C8String,
    format: CredentialFormat,
    title: C8String,
    subtitle: Option<C8String>,
    disclaimer: Option<C8String>,
    warning: Option<C8String>,
    fields: Vec<ResolvedFieldConfig>,
    metadata: Option<Value>,
    icon: Option<Vec<u8>>,
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: bool,
    claims: Value,
    transaction_data_types: Vec<TransactionDataType>,
    ts12_metadata: Vec<ResolvedTs12Metadata>,
}

#[derive(Debug, Clone)]
struct ResolvedFieldConfig {
    path: ClaimsPathPointer,
    display_name: C8String,
    display_value: Option<C8String>,
}

#[derive(Debug, Clone)]
struct ResolvedTs12Metadata {
    data_type: Ts12DataType,
    claims: Vec<ResolvedTs12ClaimMetadata>,
    ui_labels: ResolvedTs12UiLabels,
}

#[derive(Debug, Clone)]
struct ResolvedTs12ClaimMetadata {
    path: ClaimsPathPointer,
    display: Vec<ResolvedTs12LocalizedLabel>,
}

#[derive(Debug, Clone)]
struct ResolvedTs12LocalizedLabel {
    locale: String,
    label: C8String,
    description: Option<C8String>,
}

#[derive(Debug, Clone)]
struct ResolvedTs12LocalizedValue {
    locale: String,
    value: C8String,
}

type ResolvedTs12UiLabels = Vec<(String, Vec<ResolvedTs12LocalizedValue>)>;

impl ResolvedTs12Metadata {
    fn as_borrowed(&self) -> Ts12TransactionMetadata<'_> {
        let claims = self
            .claims
            .iter()
            .map(|claim| Ts12ClaimMetadata {
                path: claim.path.clone(),
                display: claim
                    .display
                    .iter()
                    .map(|label| Ts12LocalizedLabel {
                        locale: label.locale.clone(),
                        label: Cow::Borrowed(label.label.as_c8_str()),
                        description: label
                            .description
                            .as_ref()
                            .map(|value| Cow::Borrowed(value.as_c8_str())),
                    })
                    .collect(),
            })
            .collect();
        let ui_labels: Ts12UiLabels<'_> = self
            .ui_labels
            .iter()
            .map(|(key, values)| {
                let values = values
                    .iter()
                    .map(|value| Ts12LocalizedValue {
                        locale: value.locale.clone(),
                        value: Cow::Borrowed(value.value.as_c8_str()),
                    })
                    .collect();
                (key.clone(), values)
            })
            .collect();
        Ts12TransactionMetadata {
            data_type: self.data_type.clone(),
            claims,
            ui_labels,
        }
    }
}

#[derive(Debug, Clone)]
struct PackageStore {
    credentials: Vec<ResolvedCredential>,
    openid4vp: OpenId4VpConfig,
    log_level: Option<LogLevel>,
    dcql: PlanOptions,
}

impl PackageStore {
    fn from_config(config: PackageConfig) -> Result<Self, String> {
        let default_prefix = config.default_id_prefix.as_deref();

        let credentials = config
            .credentials
            .into_iter()
            .enumerate()
            .filter_map(|(index, credential)| {
                resolve_credential(credential, index, default_prefix)
                    .inspect_err(|err| {
                        dcapi_matcher::diagnostics::warn(format!(
                            "credential package warning: {}",
                            err
                        ));
                    })
                    .ok()
            })
            .collect::<Vec<_>>();

        Ok(Self {
            credentials,
            openid4vp: config.openid4vp,
            log_level: config.log_level,
            dcql: config.dcql,
        })
    }

    fn get(&self, idx: usize) -> Option<&ResolvedCredential> {
        self.credentials.get(idx)
    }

    fn dcql_options(&self) -> PlanOptions {
        self.dcql.clone()
    }
}

impl CredentialStore for PackageStore {
    type CredentialRef = usize;
    type ReadError = std::io::Error;

    fn from_reader(reader: &mut dyn std::io::Read) -> Result<Self, Self::ReadError> {
        let config: PackageConfig = serde_json::from_reader(reader)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Self::from_config(config)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| format.is_none_or(|requested| credential.format == requested))
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.get(*cred)
            .map(|credential| credential.format)
            .unwrap_or(CredentialFormat::Unknown)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.get(*cred)
            .map(|credential| credential.vcts.iter().any(|entry| entry == vct))
            .unwrap_or(false)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(*cred)
            .map(|credential| credential.holder_binding)
            .unwrap_or(false)
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.get(*cred)
            .and_then(|credential| credential.doctype.as_deref())
            .map(|value| value == doctype)
            .unwrap_or(false)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &TransactionData,
    ) -> bool {
        let Some(credential) = self.get(*cred) else {
            return false;
        };
        if !credential
            .transaction_data_types
            .iter()
            .any(|entry| entry.r#type == transaction_data.r#type)
        {
            return false;
        }

        let requires_subtype = credential.ts12_metadata.iter().any(|meta| {
            meta.data_type.r#type == transaction_data.r#type && meta.data_type.subtype.is_some()
        });
        if !requires_subtype {
            return true;
        }

        let Some(subtype) = transaction_data_subtype(transaction_data) else {
            return false;
        };
        credential.ts12_metadata.iter().any(|meta| {
            meta.data_type.r#type == transaction_data.r#type
                && meta.data_type.subtype.as_deref() == Some(subtype)
        })
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        self.get(*cred)
            .and_then(|credential| dcapi_dcql::select_nodes(&credential.claims, path).ok())
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let Some(credential) = self.get(*cred) else {
            return ValueMatch::NoMatch;
        };
        let Ok(nodes) = dcapi_dcql::select_nodes(&credential.claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values.iter().any(|value| match value {
                ClaimValue::String(v) => node.as_str() == Some(v),
                ClaimValue::Integer(v) => node.as_i64() == Some(*v),
                ClaimValue::Boolean(v) => node.as_bool() == Some(*v),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for PackageStore {
    fn credential_id(&self, cred: &Self::CredentialRef) -> Cow<'_, C8Str> {
        self.get(*cred)
            .map(|credential| Cow::Borrowed(credential.id.as_c8_str()))
            .unwrap_or(Cow::Borrowed(c8!("")))
    }

    fn credential_title(&self, cred: &Self::CredentialRef) -> Cow<'_, C8Str> {
        self.get(*cred)
            .map(|credential| Cow::Borrowed(credential.title.as_c8_str()))
            .unwrap_or(Cow::Borrowed(c8!("")))
    }

    fn credential_icon(&self, cred: &Self::CredentialRef) -> Option<&[u8]> {
        self.get(*cred)
            .and_then(|credential| credential.icon.as_deref())
    }

    fn credential_subtitle(&self, cred: &Self::CredentialRef) -> Option<Cow<'_, C8Str>> {
        self.get(*cred).and_then(|credential| {
            credential
                .subtitle
                .as_ref()
                .map(|value| Cow::Borrowed(value.as_c8_str()))
        })
    }

    fn credential_disclaimer(&self, cred: &Self::CredentialRef) -> Option<Cow<'_, C8Str>> {
        self.get(*cred).and_then(|credential| {
            credential
                .disclaimer
                .as_ref()
                .map(|value| Cow::Borrowed(value.as_c8_str()))
        })
    }

    fn credential_warning(&self, cred: &Self::CredentialRef) -> Option<Cow<'_, C8Str>> {
        self.get(*cred).and_then(|credential| {
            credential
                .warning
                .as_ref()
                .map(|value| Cow::Borrowed(value.as_c8_str()))
        })
    }

    fn get_credential_field_label<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        if path_has_wildcard(path) {
            return None;
        }
        let credential = self.get(*cred)?;
        if let Some(metadata) = credential.metadata.as_ref()
            && let Some(display_name) = claim_display_name_from_metadata(metadata, path)
        {
            return c8string_from_str(display_name).map(Cow::Owned);
        }
        credential
            .fields
            .iter()
            .find(|field| path_matches(&field.path, path))
            .map(|field| Cow::Borrowed(field.display_name.as_c8_str()))
    }

    fn get_credential_field_value<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        if path_has_wildcard(path) {
            return None;
        }
        let credential = self.get(*cred)?;
        if let Some(field) = credential
            .fields
            .iter()
            .find(|field| path_matches(&field.path, path))
            && let Some(value) = field.display_value.as_deref()
        {
            return Some(Cow::Borrowed(value));
        }
        value_from_claims(&credential.claims, path)
            .and_then(c8string_from_str)
            .map(Cow::Owned)
    }

    fn supports_protocol(&self, _cred: &Self::CredentialRef, _protocol: &str) -> bool {
        true
    }

    fn verify_openid4vp_signed_request(
        &self,
        _protocol: &str,
        _request: &dcapi_matcher::OpenId4VpSignedEnvelope,
    ) -> bool {
        true
    }

    fn openid4vp_config(&self) -> OpenId4VpConfig {
        self.openid4vp.clone()
    }

    fn locales(&self) -> &[&str] {
        static LOCALES: [&str; 1] = ["en"];
        &LOCALES
    }

    fn log_level(&self) -> Option<LogLevel> {
        self.log_level
    }

    fn ts12_transaction_metadata<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata<'a>> {
        let data_type = ts12_data_type_from_transaction_data(transaction_data);
        self.get(*cred).and_then(|credential| {
            credential
                .ts12_metadata
                .iter()
                .find(|entry| entry.data_type == data_type)
                .map(ResolvedTs12Metadata::as_borrowed)
        })
    }

    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
        payload: &Value,
        _metadata: &Ts12TransactionMetadata<'a>,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary<'a>> {
        if transaction_data.r#type != "urn:eudi:sca:payment:1" {
            return None;
        }

        let (merchant, amount) = payment_summary_fields(payload);
        Some(Ts12PaymentSummary {
            merchant_name: Cow::Owned(merchant),
            transaction_amount: Cow::Owned(amount),
            additional_info: None,
        })
    }
}

fn payment_summary_fields(payload: &Value) -> (C8String, C8String) {
    let mut merchant = "";
    let mut currency = "";
    let mut amount_value: Option<String> = None;

    if let Some(obj) = payload.as_object() {
        if let Some(payee) = obj.get("payee").and_then(Value::as_object) {
            merchant = payee
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| payee.get("id").and_then(Value::as_str))
                .unwrap_or("");
        }
        currency = obj.get("currency").and_then(Value::as_str).unwrap_or("");
        if let Some(amount) = obj.get("amount") {
            amount_value = match amount {
                Value::Number(num) => Some(num.to_string()),
                Value::String(text) => Some(text.clone()),
                _ => None,
            };
        }
    }

    let transaction_amount = match (amount_value, currency.is_empty()) {
        (Some(amount), false) => format!("{amount} {currency}"),
        (Some(amount), true) => amount,
        (None, false) => currency.to_string(),
        (None, true) => String::new(),
    };

    let merchant_c8 = c8string_from_str(merchant).unwrap_or_default();
    let amount_c8 = c8string_from_str(&transaction_amount).unwrap_or_default();
    (merchant_c8, amount_c8)
}

fn resolve_credential(
    credential: CredentialConfig,
    index: usize,
    default_id_prefix: Option<&str>,
) -> Result<ResolvedCredential, String> {
    if credential.format.trim().is_empty() {
        return Err("credential format must be non-empty".to_string());
    }
    let fallback_prefix = default_id_prefix.unwrap_or(credential.format.as_str());
    let id = credential
        .id
        .map(Into::into)
        .unwrap_or_else(|| c8format!("{fallback_prefix}-{index}"));
    let format = CredentialFormat::from(credential.format.as_str());
    let title = credential
        .title
        .map(Into::into)
        .unwrap_or_else(|| id.clone());
    let claims = credential
        .claims
        .unwrap_or_else(|| Value::Object(Map::new()));
    let icon = match credential.icon {
        Some(icon) => decode_icon(icon)?,
        None => None,
    };
    let holder_binding = credential.holder_binding.unwrap_or(true);
    let fields = credential
        .fields
        .into_iter()
        .map(|field| ResolvedFieldConfig {
            path: field.path,
            display_name: field.display_name.into(),
            display_value: field.display_value.map(Into::into),
        })
        .collect::<Vec<_>>();
    let ts12_metadata = credential
        .transaction_data_types
        .into_iter()
        .map(resolve_ts12_metadata)
        .collect::<Vec<_>>();
    let transaction_data_types = ts12_metadata
        .iter()
        .map(|entry| TransactionDataType {
            r#type: entry.data_type.r#type.clone(),
        })
        .collect();

    Ok(ResolvedCredential {
        id,
        format,
        title,
        subtitle: credential.subtitle.map(Into::into),
        disclaimer: credential.disclaimer.map(Into::into),
        warning: credential.warning.map(Into::into),
        fields,
        metadata: credential.metadata,
        icon,
        vcts: credential.vcts,
        doctype: credential.doctype,
        holder_binding,
        claims,
        transaction_data_types,
        ts12_metadata,
    })
}

fn resolve_ts12_metadata(config: Ts12MetadataConfig) -> ResolvedTs12Metadata {
    let claims = config
        .claims
        .into_iter()
        .map(|claim| ResolvedTs12ClaimMetadata {
            path: claim.path,
            display: claim
                .display
                .into_iter()
                .map(|label| ResolvedTs12LocalizedLabel {
                    locale: label.locale,
                    label: label.label.into(),
                    description: label.description.map(Into::into),
                })
                .collect(),
        })
        .collect();
    let ui_labels: ResolvedTs12UiLabels = config
        .ui_labels
        .into_iter()
        .map(|entry| {
            let values = entry
                .values
                .into_iter()
                .map(|value| ResolvedTs12LocalizedValue {
                    locale: value.locale,
                    value: value.value.into(),
                })
                .collect();
            (entry.key, values)
        })
        .collect();
    ResolvedTs12Metadata {
        data_type: config.data_type,
        claims,
        ui_labels,
    }
}

fn claim_display_name_from_metadata<'a>(
    metadata: &'a Value,
    claim_path: &ClaimsPathPointer,
) -> Option<&'a str> {
    for claims in claims_description_arrays(metadata) {
        for entry in claims {
            let path_value = entry.get("path")?;
            let parsed: ClaimsPathPointer = serde_json::from_value(path_value.clone()).ok()?;
            if !path_matches(&parsed, claim_path) {
                continue;
            }
            if let Some(display) = entry.get("display").and_then(Value::as_array) {
                for display_entry in display {
                    if let Some(name) = display_entry.get("name").and_then(Value::as_str)
                        && !name.is_empty()
                    {
                        return Some(name);
                    }
                }
            }
        }
    }
    None
}

fn claims_description_arrays(metadata: &Value) -> Vec<&Vec<Value>> {
    let mut out = Vec::new();
    if let Some(entries) = metadata.get("claims").and_then(Value::as_array) {
        out.push(entries);
    }
    if let Some(entries) = metadata
        .get("credential_metadata")
        .and_then(|value| value.get("claims"))
        .and_then(Value::as_array)
    {
        out.push(entries);
    }
    out
}

fn value_from_claims<'a>(claims: &'a Value, path: &ClaimsPathPointer) -> Option<&'a str> {
    let Ok(nodes) = dcapi_dcql::select_nodes(claims, path) else {
        return None;
    };
    nodes.first().and_then(|value| value.as_str())
}

fn transaction_data_subtype(transaction_data: &TransactionData) -> Option<&str> {
    transaction_data
        .extra
        .get("subtype")
        .and_then(Value::as_str)
}

fn ts12_data_type_from_transaction_data(transaction_data: &TransactionData) -> Ts12DataType {
    Ts12DataType {
        r#type: transaction_data.r#type.clone(),
        subtype: transaction_data_subtype(transaction_data).map(|value| value.to_string()),
    }
}

fn path_has_wildcard(path: &ClaimsPathPointer) -> bool {
    path.iter()
        .any(|segment| matches!(segment, PathElement::Wildcard))
}

fn c8string_from_str(value: &str) -> Option<C8String> {
    C8String::from_string(value.to_string()).ok()
}

fn decode_icon(icon: IconConfig) -> Result<Option<Vec<u8>>, String> {
    match icon {
        IconConfig::Bytes(bytes) => Ok(if bytes.is_empty() { None } else { Some(bytes) }),
        IconConfig::Base64(value) => {
            if value.is_empty() {
                return Ok(None);
            }
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::URL_SAFE_NO_PAD,
            ] {
                if let Ok(bytes) = engine.decode(value.as_bytes()) {
                    return Ok(if bytes.is_empty() { None } else { Some(bytes) });
                }
            }
            Err("invalid icon base64".to_string())
        }
    }
}

/// Credman matcher entrypoint for aptitude consortium config packages.
#[dcapi_matcher]
fn matcher_entrypoint(store: PackageStore) {
    dcapi_matcher::diagnostics::set_level(store.log_level);
    info(get_request_string());
    let options = MatcherOptions {
        dcql: store.dcql_options(),
    };
    let Ok(matched) = match_dc_api_request(&store, &options) else {
        return;
    };
    matched.render();
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcapi_dcql::{CredentialSetOptionMode, OptionalCredentialSetsMode};
    use dcapi_matcher::{CredentialEntry, MatcherOptions, MatcherResult};
    use serde_json::json;
    use std::io::Cursor;
    use std::sync::Mutex;

    static REQUEST_LOCK: Mutex<()> = Mutex::new(());

    fn package_payload() -> &'static str {
        r#"{"default_id_prefix":"cred-","openid4vp":{"enabled":true,"supported_request_protocols":["openid4vp-v1-unsigned","openid4vp-v1-signed","openid4vp-v1-multisigned"],"supported_response_modes":["dc_api","dc_api.jwt"],"supported_response_types":["vp_token"],"supported_query_methods":["dcql_query"],"supported_request_parameters":["transaction_data"]},"dcql":{"credential_set_option_mode":"first_satisfiable_only","optional_credential_sets_mode":"prefer_present"},"credentials":[{"id":"mdoc-1","format":"mso_mdoc","title":"Drivers License","subtitle":"Issued by Utopia","icon":"/9j/4AAQSkZJRgABAQEASABIAAD//gATQ3JlYXRlZCB3aXRoIEdJTVD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wgARCABLAGQDAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAf/xAAWAQEBAQAAAAAAAAAAAAAAAAAABgj/2gAMAwEAAhADEAAAAZzC6pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAEFAgL/xAAUEQEAAAAAAAAAAAAAAAAAAABw/9oACAEDAQE/AQL/xAAUEQEAAAAAAAAAAAAAAAAAAABw/9oACAECAQE/AQL/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAY/AgL/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAE/IQL/2gAMAwEAAgADAAAAEP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/8QAFBEBAAAAAAAAAAAAAAAAAAAAcP/aAAgBAwEBPxAC/8QAFBEBAAAAAAAAAAAAAAAAAAAAcP/aAAgBAgEBPxAC/8QAFBABAAAAAAAAAAAAAAAAAAAAcP/aAAgBAQABPxAC/9k=","doctype":"org.iso.18013.5.1.mDL","fields":[{"path":["org.iso.18013.5.1","family_name"],"display_name":"Family Name"},{"path":["org.iso.18013.5.1","given_name"],"display_name":"Given Name"}],"claims":{"org.iso.18013.5.1":{"family_name":"Glastra","given_name":"Timo"}}},{"id":"pid-1","format":"dc+sd-jwt","title":"PID","subtitle":"Issued by Utopia","icon":"/9j/4AAQSkZJRgABAQEASABIAAD//gATQ3JlYXRlZCB3aXRoIEdJTVD/2wBDAAMCAgMCAgMDAwMEAwMEBQgFBQQEBQoHBwYIDAoMDAsKCwsNDhIQDQ4RDgsLEBYQERMUFRUVDA8XGBYUGBIUFRT/2wBDAQMEBAUEBQkFBQkUDQsNFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBT/wgARCABLAGQDAREAAhEBAxEB/8QAFQABAQAAAAAAAAAAAAAAAAAAAAf/xAAWAQEBAQAAAAAAAAAAAAAAAAAABgj/2gAMAwEAAhADEAAAAZzC6pAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAH/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAEFAgL/xAAUEQEAAAAAAAAAAAAAAAAAAABw/9oACAEDAQE/AQL/xAAUEQEAAAAAAAAAAAAAAAAAAABw/9oACAECAQE/AQL/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAY/AgL/xAAUEAEAAAAAAAAAAAAAAAAAAABw/9oACAEBAAE/IQL/2gAMAwEAAgADAAAAEP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/8QAFBEBAAAAAAAAAAAAAAAAAAAAcP/aAAgBAwEBPxAC/8QAFBEBAAAAAAAAAAAAAAAAAAAAcP/aAAgBAgEBPxAC/8QAFBABAAAAAAAAAAAAAAAAAAAAcP/aAAgBAQABPxAC/9k=","vcts":["eu.europa.ec.eudi.pid.1"],"claims":{"first_name":"Timo","address":{"city":"Somewhere"}}}],"log_level":"debug"}"#
    }

    #[test]
    fn parses_credential_package_fixture() {
        let mut cursor = Cursor::new(package_payload().as_bytes());
        let store = PackageStore::from_reader(&mut cursor).expect("package should parse");

        assert_eq!(store.credentials.len(), 2);
        assert_eq!(store.credentials[0].id.as_c8_str().as_str(), "mdoc-1");
        assert_eq!(
            store.credentials[0].doctype.as_deref(),
            Some("org.iso.18013.5.1.mDL")
        );
        assert_eq!(store.credentials[0].fields.len(), 2);
        assert_eq!(store.credentials[1].id.as_c8_str().as_str(), "pid-1");
        assert_eq!(
            store.credentials[1].vcts,
            vec!["eu.europa.ec.eudi.pid.1".to_string()]
        );
        assert!(matches!(store.log_level, Some(LogLevel::Debug)));
        assert_eq!(
            store.dcql.credential_set_option_mode,
            CredentialSetOptionMode::FirstSatisfiableOnly
        );
        assert_eq!(
            store.dcql.optional_credential_sets_mode,
            OptionalCredentialSetsMode::PreferPresent
        );
    }

    #[test]
    fn matches_mdl_claims_for_dcql_request() {
        let _guard = REQUEST_LOCK.lock().unwrap();
        let mut cursor = Cursor::new(package_payload().as_bytes());
        let store = PackageStore::from_reader(&mut cursor).expect("package should parse");
        let request = json!({
            "requests": [{
                "protocol": "openid4vp-v1-unsigned",
                "data": {
                    "dcql_query": {
                        "credentials": [{
                            "id": "0",
                            "format": "mso_mdoc",
                            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                            "claims": [
                                {
                                    "id": "given_name",
                                    "path": ["org.iso.18013.5.1", "given_name"],
                                    "intent_to_retain": false
                                },
                                {
                                    "id": "family_name",
                                    "path": ["org.iso.18013.5.1", "family_name"],
                                    "intent_to_retain": false
                                }
                            ]
                        }],
                        "credential_sets": [{
                            "options": [["0"]],
                            "purpose": "mDL (mdoc) - Names"
                        }]
                    }
                }
            }]
        })
        .to_string();

        android_credman_sys::test_shim::set_request(request.as_bytes());

        let options = MatcherOptions {
            dcql: store.dcql_options(),
        };
        let response = match_dc_api_request(&store, &options).expect("match should succeed");
        assert!(!response.results.is_empty());

        let set = match &response.results[0] {
            MatcherResult::Group(set) => set,
            other => panic!("expected group result, got {other:?}"),
        };
        let entry = set
            .slots
            .first()
            .and_then(|slot| slot.alternatives.first())
            .expect("expected entry");
        let fields = match entry {
            CredentialEntry::StringId(entry) => entry.fields.as_ref(),
            CredentialEntry::Payment(entry) => entry.fields.as_ref(),
        };

        let mut has_family = false;
        let mut has_given = false;
        for field in fields {
            let name = field.display_name.to_str().unwrap_or("");
            let value = field
                .display_value
                .as_deref()
                .and_then(|value| value.to_str().ok())
                .unwrap_or("");
            if name == "Family Name" && value == "Glastra" {
                has_family = true;
            }
            if name == "Given Name" && value == "Timo" {
                has_given = true;
            }
        }
        assert!(has_family, "expected Family Name field");
        assert!(has_given, "expected Given Name field");
    }
}
