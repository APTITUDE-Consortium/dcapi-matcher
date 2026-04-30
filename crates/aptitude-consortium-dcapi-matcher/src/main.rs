use android_credman::{CredmanRender, get_request_string};
use base64::Engine;
use c8str::{C8Str, C8String, c8, c8format};
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement, PlanOptions,
    TransactionData, ValueMatch, path_matches, select_nodes,
};
use dcapi_matcher::diagnostics::info;
use dcapi_matcher::{
    LogLevel, MatcherOptions, MatcherStore, OpenId4VpConfig, Ts12ClaimMetadata, Ts12DataType,
    Ts12PaymentSummary, Ts12TransactionMetadata, dcapi_matcher, match_dc_api_request,
};
use serde::Deserialize;
use serde_json::{Map, Value};
use std::borrow::Cow;

#[repr(transparent)]
#[derive(Debug, Clone)]
struct C8StringValue(C8String);

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
    #[serde(default, deserialize_with = "deserialize_payment_sca_mappings")]
    payment_sca: Vec<PaymentScaTypeConfig>,
    log_level: Option<LogLevel>,
    #[serde(default)]
    credentials: Vec<CredentialConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct PaymentScaTypeConfig {
    #[serde(rename = "type")]
    data_type: String,
    payee: ClaimsPathPointer,
    amount: ClaimsPathPointer,
    #[serde(default)]
    additional_info: Option<ClaimsPathPointer>,
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
    #[serde(default, deserialize_with = "deserialize_ts12_metadata_configs")]
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
    #[serde(rename = "type")]
    data_type: String,
    #[serde(default, deserialize_with = "deserialize_ts12_claim_configs")]
    claims: Vec<Ts12ClaimConfig>,
}

#[derive(Debug, Deserialize)]
struct Ts12ClaimConfig {
    path: ClaimsPathPointer,
    #[serde(default)]
    mandatory: bool,
    #[serde(default)]
    value_type: Option<String>,
    #[serde(
        default,
        rename = "display",
        deserialize_with = "deserialize_displayable_claim"
    )]
    displayable: bool,
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
    ts12_metadata: Vec<Ts12TransactionMetadata>,
}

#[derive(Debug, Clone)]
struct ResolvedFieldConfig {
    path: ClaimsPathPointer,
    display_name: C8String,
    display_value: Option<C8String>,
}

#[derive(Debug, Clone)]
struct PackageStore {
    credentials: Vec<ResolvedCredential>,
    openid4vp: OpenId4VpConfig,
    payment_sca: Vec<PaymentScaTypeConfig>,
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
            payment_sca: config.payment_sca,
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

    fn payment_sca_summary(
        &self,
        transaction_data: &TransactionData,
    ) -> Option<(C8String, C8String, Option<C8String>)> {
        let mapping = self
            .payment_sca
            .iter()
            .find(|mapping| mapping.data_type == transaction_data.r#type)?;
        let data = transaction_data_as_value(transaction_data);
        let merchant = string_at_path(&data, &mapping.payee)?;
        let amount = string_at_path(&data, &mapping.amount)?;
        let additional_info = mapping
            .additional_info
            .as_ref()
            .and_then(|path| string_at_path(&data, path))
            .and_then(|value| c8string_from_str(&value));

        Some((
            c8string_from_str(&merchant)?,
            c8string_from_str(&amount)?,
            additional_info,
        ))
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
        let Some(metadata) = credential
            .ts12_metadata
            .iter()
            .find(|entry| entry.data_type.r#type == transaction_data.r#type)
        else {
            return false;
        };
        let Some(payload) = transaction_data_payload(transaction_data) else {
            return false;
        };
        metadata.is_payload_compatible(payload)
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

    fn log_level(&self) -> Option<LogLevel> {
        self.log_level
    }

    fn ts12_transaction_metadata(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata> {
        self.get(*cred).and_then(|credential| {
            credential
                .ts12_metadata
                .iter()
                .find(|entry| entry.data_type.r#type == transaction_data.r#type)
                .cloned()
        })
    }

    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
        _payload: &Value,
        _metadata: &Ts12TransactionMetadata,
    ) -> Option<Ts12PaymentSummary<'a>> {
        let (merchant, amount, additional_info) = self.payment_sca_summary(transaction_data)?;

        Some(Ts12PaymentSummary {
            merchant_name: Cow::Owned(merchant),
            transaction_amount: Cow::Owned(amount),
            additional_info: additional_info.map(Cow::Owned),
        })
    }
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
        ts12_metadata,
    })
}

fn resolve_ts12_metadata(config: Ts12MetadataConfig) -> Ts12TransactionMetadata {
    let claims = config
        .claims
        .into_iter()
        .map(|claim| Ts12ClaimMetadata {
            path: claim.path,
            mandatory: claim.mandatory,
            value_type: claim.value_type,
            displayable: claim.displayable,
        })
        .collect();
    Ts12TransactionMetadata {
        data_type: Ts12DataType {
            r#type: config.data_type,
        },
        claims,
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

fn deserialize_ts12_claim_configs<'de, D>(deserializer: D) -> Result<Vec<Ts12ClaimConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect(),
        _ => Vec::new(),
    })
}

fn deserialize_displayable_claim<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(value.as_array().is_some_and(|entries| !entries.is_empty()))
}

fn deserialize_ts12_metadata_configs<'de, D>(
    deserializer: D,
) -> Result<Vec<Ts12MetadataConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect(),
        Value::Object(entries) => entries
            .into_iter()
            .filter_map(|(data_type, value)| {
                let mut object = value.as_object()?.clone();
                object.insert("type".to_string(), Value::String(data_type));
                serde_json::from_value(Value::Object(object)).ok()
            })
            .collect(),
        _ => Vec::new(),
    })
}

fn deserialize_payment_sca_mappings<'de, D>(
    deserializer: D,
) -> Result<Vec<PaymentScaTypeConfig>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    Ok(match value {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect(),
        Value::Object(entries) => entries
            .into_iter()
            .filter_map(|(data_type, value)| {
                let mut object = value.as_object()?.clone();
                object.insert("type".to_string(), Value::String(data_type));
                serde_json::from_value(Value::Object(object)).ok()
            })
            .collect(),
        _ => Vec::new(),
    })
}

fn value_from_claims<'a>(claims: &'a Value, path: &ClaimsPathPointer) -> Option<&'a str> {
    let Ok(nodes) = dcapi_dcql::select_nodes(claims, path) else {
        return None;
    };
    nodes.first().and_then(|value| value.as_str())
}

fn transaction_data_payload(transaction_data: &TransactionData) -> Option<&Value> {
    transaction_data.extra.get("payload")
}

fn transaction_data_as_value(transaction_data: &TransactionData) -> Value {
    let mut object = Map::new();
    object.insert(
        "type".to_string(),
        Value::String(transaction_data.r#type.clone()),
    );
    object.insert(
        "credential_ids".to_string(),
        Value::Array(
            transaction_data
                .credential_ids
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    if let Some(alg) = &transaction_data.transaction_data_hashes_alg {
        object.insert(
            "transaction_data_hashes_alg".to_string(),
            Value::String(alg.clone()),
        );
    }
    for (key, value) in &transaction_data.extra {
        object.insert(key.clone(), value.clone());
    }
    Value::Object(object)
}

fn string_at_path(root: &Value, path: &ClaimsPathPointer) -> Option<String> {
    let value = select_nodes(root, path).ok()?.into_iter().next()?;
    match value {
        Value::String(text) if !text.is_empty() => Some(text.clone()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
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

    #[test]
    fn ts12_metadata_object_map_controls_payload_compatibility() {
        let config = json!({
            "payment_sca": {
                "urn:eudi:sca:eu.europa.ec:payment:single:1": {
                    "payee": ["payload", "payee", "name"],
                    "amount": ["payload", "amount"]
                }
            },
            "credentials": [{
                "id": "sca-1",
                "format": "dc+sd-jwt",
                "title": "SCA",
                "vcts": ["vct:sca"],
                "transaction_data_types": {
                    "urn:eudi:sca:eu.europa.ec:payment:single:1": {
                        "claims": [
                            { "path": ["transaction_id"], "mandatory": true },
                            {
                                "path": ["amount"],
                                "mandatory": true,
                                "display": [{ "locale": "en", "name": "Amount" }]
                            },
                            {
                                "path": ["payee", "name"],
                                "mandatory": true,
                                "display": [{ "locale": "en", "name": "Payee" }]
                            }
                        ],
                        "ui_labels": {
                            "affirmative_action_label": [
                                { "locale": "en", "value": "Confirm" }
                            ]
                        }
                    }
                }
            }]
        })
        .to_string();
        let mut cursor = Cursor::new(config.as_bytes());
        let store = PackageStore::from_reader(&mut cursor).expect("package should parse");
        let matching = transaction_data(json!({
            "type": "urn:eudi:sca:eu.europa.ec:payment:single:1",
            "credential_ids": ["sca"],
            "payload": {
                "transaction_id": "tx-1",
                "amount": "42.50",
                "payee": { "name": "Example Shop" }
            }
        }));
        let extra_field = transaction_data(json!({
            "type": "urn:eudi:sca:eu.europa.ec:payment:single:1",
            "credential_ids": ["sca"],
            "payload": {
                "transaction_id": "tx-1",
                "amount": "42.50",
                "payee": { "name": "Example Shop" },
                "unexpected": "x"
            }
        }));

        assert!(store.can_sign_transaction_data(&0, &matching));
        assert!(!store.can_sign_transaction_data(&0, &extra_field));
    }

    #[test]
    fn ts12_transaction_without_payment_sca_mapping_is_signable_if_payload_matches() {
        let config = json!({
            "credentials": [{
                "id": "sca-1",
                "format": "dc+sd-jwt",
                "title": "SCA",
                "vcts": ["vct:sca"],
                "transaction_data_types": {
                    "urn:eudi:sca:eu.europa.ec:payment:single:1": {
                        "claims": [
                            { "path": ["amount"], "mandatory": true },
                            { "path": ["payee", "name"], "mandatory": true }
                        ]
                    }
                }
            }]
        })
        .to_string();
        let mut cursor = Cursor::new(config.as_bytes());
        let store = PackageStore::from_reader(&mut cursor).expect("package should parse");
        let td = transaction_data(json!({
            "type": "urn:eudi:sca:eu.europa.ec:payment:single:1",
            "credential_ids": ["sca"],
            "payload": {
                "amount": "42.50",
                "payee": { "name": "Example Shop" }
            }
        }));

        assert!(store.can_sign_transaction_data(&0, &td));
    }

    #[test]
    fn payment_sca_config_maps_multiple_types_to_payment_summary() {
        let config = json!({
            "payment_sca": {
                "urn:eudi:sca:eu.europa.ec:payment:single:1": {
                    "payee": ["payload", "payee", "name"],
                    "amount": ["payload", "amount"]
                },
                "urn:eudi:sca:example.bank:payment:instant:1": {
                    "payee": ["payload", "recipient", "display_name"],
                    "amount": ["payload", "total"],
                    "additional_info": ["payload", "reference"]
                }
            },
            "credentials": [{
                "id": "sca-1",
                "format": "dc+sd-jwt",
                "title": "SCA",
                "vcts": ["vct:sca"],
                "transaction_data_types": {
                    "urn:eudi:sca:example.bank:payment:instant:1": {
                        "claims": [
                            { "path": ["recipient", "display_name"], "mandatory": true, "display": [{ "locale": "en", "name": "Payee" }] },
                            { "path": ["total"], "mandatory": true, "display": [{ "locale": "en", "name": "Amount" }] },
                            { "path": ["reference"], "display": [{ "locale": "en", "name": "Reference" }] }
                        ],
                        "ui_labels": {
                            "affirmative_action_label": [{ "locale": "en", "value": "Confirm" }]
                        }
                    }
                }
            }]
        })
        .to_string();
        let mut cursor = Cursor::new(config.as_bytes());
        let store = PackageStore::from_reader(&mut cursor).expect("package should parse");
        let td = transaction_data(json!({
            "type": "urn:eudi:sca:example.bank:payment:instant:1",
            "credential_ids": ["sca"],
            "payload": {
                "recipient": { "display_name": "Alt Shop" },
                "total": "10.00 EUR",
                "reference": "Order 123"
            }
        }));
        let metadata = store.ts12_transaction_metadata(&0, &td).unwrap();
        let summary = store
            .ts12_payment_summary(&0, &td, td.extra.get("payload").unwrap(), &metadata)
            .expect("payment summary");

        assert_eq!(summary.merchant_name.as_ref().as_str(), "Alt Shop");
        assert_eq!(summary.transaction_amount.as_ref().as_str(), "10.00 EUR");
        assert_eq!(
            summary.additional_info.as_deref().map(C8Str::as_str),
            Some("Order 123")
        );
    }

    fn transaction_data(value: Value) -> TransactionData {
        serde_json::from_value(value).expect("transaction_data should parse")
    }
}
