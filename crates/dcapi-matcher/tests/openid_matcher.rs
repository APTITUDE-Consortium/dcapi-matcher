use android_credman::CredmanRender;
use android_credman::test_shim::{self, DisplayEvent};
use base64::Engine;
use c8str::{C8Str, C8String, c8, c8format};
use dcapi_dcql::{
    ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore, PathElement,
    TransactionDataType, ValueMatch,
};
use dcapi_matcher::{
    CredentialEntry, DefaultProfile, Field, MatcherError, MatcherOptions, MatcherResult,
    MatcherStore, PROTOCOL_OPENID4VP_V1_MULTISIGNED, PROTOCOL_OPENID4VP_V1_SIGNED,
    PROTOCOL_OPENID4VP_V1_UNSIGNED, Ts12ClaimMetadata, Ts12DataType, Ts12LocalizedLabel,
    Ts12LocalizedValue, Ts12PaymentSummary, Ts12TransactionMetadata, decode_json_package,
    match_dc_api_request as match_dc_api_request_internal,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::CStr;
use std::sync::Mutex;

const TS12_TYPE_PAYMENT: &str = "urn:eudi:sca:payment:1";
const TS12_TYPE_GENERIC: &str = "urn:eudi:sca:generic:1";

static REQUEST_LOCK: Mutex<()> = Mutex::new(());

fn match_dc_api_request<'a>(
    request: &str,
    store: &'a impl MatcherStore,
    options: &MatcherOptions,
) -> Result<dcapi_matcher::MatcherResponse<'a>, MatcherError> {
    let _guard = REQUEST_LOCK.lock().unwrap();
    test_shim::set_request(request.as_bytes());
    match_dc_api_request_internal(store, options, &DefaultProfile)
}

fn unsupported_reader<T>() -> Result<T, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "from_reader is not supported in tests",
    ))
}

fn c8string(value: &str) -> C8String {
    c8format!("{value}")
}

fn transaction_data_subtype(transaction_data: &dcapi_dcql::TransactionData) -> Option<&str> {
    transaction_data
        .extra
        .get("subtype")
        .and_then(Value::as_str)
}

fn ts12_data_type_from_transaction_data(
    transaction_data: &dcapi_dcql::TransactionData,
) -> Ts12DataType {
    Ts12DataType {
        r#type: transaction_data.r#type.clone(),
        subtype: transaction_data_subtype(transaction_data).map(|value| value.to_string()),
    }
}

#[derive(Clone)]
struct TestCredential {
    id: C8String,
    title: C8String,
    format: CredentialFormat,
    protocols: HashSet<String>,
    vcts: Vec<String>,
    doctype: Option<String>,
    holder_binding: bool,
    claims: Value,
    transaction_data_types: Vec<TransactionDataType>,
    ts12_metadata: Vec<Ts12TransactionMetadata<'static>>,
}

struct TestStore {
    credentials: Vec<TestCredential>,
    preferred_locales: Vec<&'static str>,
}

impl TestStore {
    fn new(credentials: Vec<TestCredential>) -> Self {
        Self {
            credentials,
            preferred_locales: vec!["en"],
        }
    }

    fn get(&self, idx: usize) -> &TestCredential {
        &self.credentials[idx]
    }
}

impl CredentialStore for TestStore {
    type CredentialRef = usize;
    type ReadError = std::io::Error;

    fn from_reader(_reader: &mut dyn std::io::Read) -> Result<Self, Self::ReadError> {
        unsupported_reader()
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.credentials
            .iter()
            .enumerate()
            .filter(|(_, credential)| {
                format
                    .map(|format| credential.format == format)
                    .unwrap_or(true)
            })
            .map(|(idx, _)| idx)
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.get(*cred).format
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.get(*cred).vcts.iter().any(|entry| entry == vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(*cred).holder_binding
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.get(*cred).doctype.as_deref() == Some(doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        let credential = self.get(*cred);
        if !credential
            .transaction_data_types
            .iter()
            .any(|entry| entry.r#type == transaction_data.r#type)
        {
            return false;
        }

        let requires_subtype = credential.ts12_metadata.iter().any(|meta| {
            meta.data_type.r#type == transaction_data.r#type
                && meta.data_type.subtype.is_some()
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
        dcapi_dcql::select_nodes(&self.get(*cred).claims, path)
            .map(|nodes| !nodes.is_empty())
            .unwrap_or(false)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let Ok(nodes) = dcapi_dcql::select_nodes(&self.get(*cred).claims, path) else {
            return ValueMatch::NoMatch;
        };
        for node in nodes {
            if expected_values.iter().any(|expected| match expected {
                ClaimValue::String(value) => node.as_str() == Some(value),
                ClaimValue::Integer(value) => node.as_i64() == Some(*value),
                ClaimValue::Boolean(value) => node.as_bool() == Some(*value),
            }) {
                return ValueMatch::Match;
            }
        }
        ValueMatch::NoMatch
    }
}

impl MatcherStore for TestStore {
    fn credential_id<'a>(&'a self, cred: &Self::CredentialRef) -> Cow<'a, C8Str> {
        Cow::Borrowed(self.get(*cred).id.as_c8_str())
    }

    fn credential_title<'a>(&'a self, cred: &Self::CredentialRef) -> Cow<'a, C8Str> {
        Cow::Borrowed(self.get(*cred).title.as_c8_str())
    }

    fn get_credential_field_label<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        if path
            .iter()
            .any(|segment| matches!(segment, PathElement::Wildcard))
        {
            return None;
        }
        Some(Cow::Borrowed(c8!("name")))
    }

    fn get_credential_field_value<'a>(
        &'a self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'a, C8Str>> {
        if path
            .iter()
            .any(|segment| matches!(segment, PathElement::Wildcard))
        {
            return None;
        }
        Some(Cow::Borrowed(self.get(*cred).title.as_c8_str()))
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.get(*cred).protocols.contains(protocol)
    }

    fn ts12_transaction_metadata(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> Option<Ts12TransactionMetadata<'static>> {
        let data_type = ts12_data_type_from_transaction_data(transaction_data);
        self.get(*cred)
            .ts12_metadata
            .iter()
            .find(|meta| meta.data_type == data_type)
            .cloned()
    }

    fn ts12_payment_summary<'a>(
        &'a self,
        _cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
        payload: &Value,
        _metadata: &Ts12TransactionMetadata<'a>,
        _locale: &str,
    ) -> Option<Ts12PaymentSummary<'a>> {
        if transaction_data.r#type != TS12_TYPE_PAYMENT {
            return None;
        }
        let payload = payload.as_object()?;
        let merchant_name = payload
            .get("payee")
            .and_then(Value::as_object)
            .and_then(|payee| payee.get("name"))
            .and_then(Value::as_str)?
            .to_string();
        let amount = payload.get("amount")?.to_string();
        let currency = payload
            .get("currency")
            .and_then(Value::as_str)
            .unwrap_or("");
        let transaction_amount = if currency.is_empty() {
            amount
        } else {
            format!("{amount} {currency}")
        };
        Some(Ts12PaymentSummary {
            merchant_name: Cow::Owned(c8string(&merchant_name)),
            transaction_amount: Cow::Owned(c8string(&transaction_amount)),
            additional_info: None,
        })
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        dcapi_matcher::OpenId4VpConfig {
            enabled: true,
            allow_dcql: true,
            allow_dcql_scope: false,
            allow_transaction_data: true,
            allow_signed_requests: false,
            allow_response_mode_jwt: false,
        }
    }

    fn locales(&self) -> &[&str] {
        self.preferred_locales.as_slice()
    }
}

fn ts12_payment_metadata() -> Ts12TransactionMetadata<'static> {
    let ui_labels = vec![(
        "affirmative_action_label".to_string(),
        vec![Ts12LocalizedValue {
            locale: "en".to_string(),
            value: Cow::Borrowed(c8!("Confirm")),
        }],
    )];
    Ts12TransactionMetadata {
        data_type: Ts12DataType {
            r#type: TS12_TYPE_PAYMENT.to_string(),
            subtype: None,
        },
        claims: vec![
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("transaction_id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Transaction ID")),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("payee".to_string()),
                    PathElement::String("name".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Payee")),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("payee".to_string()),
                    PathElement::String("id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Payee ID")),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("currency".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Currency")),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("amount".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Amount")),
                    description: None,
                }],
            },
        ],
        ui_labels,
    }
}

fn ts12_generic_metadata() -> Ts12TransactionMetadata<'static> {
    let ui_labels = vec![(
        "affirmative_action_label".to_string(),
        vec![Ts12LocalizedValue {
            locale: "en".to_string(),
            value: Cow::Borrowed(c8!("Confirm")),
        }],
    )];
    Ts12TransactionMetadata {
        data_type: Ts12DataType {
            r#type: TS12_TYPE_GENERIC.to_string(),
            subtype: Some("login".to_string()),
        },
        claims: vec![
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("transaction_id".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Transaction ID")),
                    description: None,
                }],
            },
            Ts12ClaimMetadata {
                path: vec![
                    PathElement::String("payload".to_string()),
                    PathElement::String("channel".to_string()),
                ],
                display: vec![Ts12LocalizedLabel {
                    locale: "en".to_string(),
                    label: Cow::Borrowed(c8!("Channel")),
                    description: None,
                }],
            },
        ],
        ui_labels,
    }
}

fn ts12_options() -> MatcherOptions {
    MatcherOptions::default()
}

fn test_store() -> TestStore {
    TestStore::new(vec![
        TestCredential {
            id: c8string("pid-1"),
            title: c8string("PID One"),
            format: CredentialFormat::DcSdJwt,
            protocols: HashSet::from(["openid4vp-v1-unsigned".to_string()]),
            vcts: vec!["vct:pid".to_string()],
            doctype: None,
            holder_binding: true,
            claims: json!({"name": "Alice", "age": 30}),
            transaction_data_types: vec![
                TransactionDataType {
                    r#type: "payment".to_string(),
                },
                TransactionDataType {
                    r#type: TS12_TYPE_PAYMENT.to_string(),
                },
                TransactionDataType {
                    r#type: TS12_TYPE_GENERIC.to_string(),
                },
            ],
            ts12_metadata: vec![ts12_payment_metadata(), ts12_generic_metadata()],
        },
        TestCredential {
            id: c8string("pid-2"),
            title: c8string("PID Two"),
            format: CredentialFormat::DcSdJwt,
            protocols: HashSet::from(["openid4vp-v1-unsigned".to_string()]),
            vcts: vec!["vct:pid".to_string()],
            doctype: None,
            holder_binding: true,
            claims: json!({"name": "Bob", "age": 40}),
            transaction_data_types: vec![],
            ts12_metadata: vec![],
        },
        TestCredential {
            id: c8string("mdl-1"),
            title: c8string("mDL One"),
            format: CredentialFormat::MsoMdoc,
            protocols: HashSet::from(["openid4vp-v1-unsigned".to_string()]),
            vcts: vec![],
            doctype: Some("org.iso.18013.5.1.mDL".to_string()),
            holder_binding: true,
            claims: json!({"org.iso.18013.5.1": {"family_name": "Doe"}}),
            transaction_data_types: vec![],
            ts12_metadata: vec![],
        },
    ])
}

struct VpOverride<'a> {
    inner: &'a TestStore,
    config: dcapi_matcher::OpenId4VpConfig,
}

impl<'a> CredentialStore for VpOverride<'a> {
    type CredentialRef = usize;
    type ReadError = std::io::Error;

    fn from_reader(_reader: &mut dyn std::io::Read) -> Result<Self, Self::ReadError> {
        unsupported_reader()
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.inner.list_credentials(format)
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.inner.format(cred)
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.inner.has_vct(cred, vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.inner.supports_holder_binding(cred)
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.inner.has_doctype(cred, doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &dcapi_dcql::TransactionData,
    ) -> bool {
        self.inner.can_sign_transaction_data(cred, transaction_data)
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        self.inner.has_claim_path(cred, path)
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        self.inner.match_claim_value(cred, path, expected_values)
    }
}

impl<'a> MatcherStore for VpOverride<'a> {
    fn credential_id<'b>(&'b self, cred: &Self::CredentialRef) -> Cow<'b, C8Str> {
        self.inner.credential_id(cred)
    }

    fn credential_title<'b>(&'b self, cred: &Self::CredentialRef) -> Cow<'b, C8Str> {
        self.inner.credential_title(cred)
    }

    fn credential_icon<'b>(&'b self, cred: &Self::CredentialRef) -> Option<&'b [u8]> {
        self.inner.credential_icon(cred)
    }

    fn credential_subtitle<'b>(&'b self, cred: &Self::CredentialRef) -> Option<Cow<'b, C8Str>> {
        self.inner.credential_subtitle(cred)
    }

    fn credential_disclaimer<'b>(&'b self, cred: &Self::CredentialRef) -> Option<Cow<'b, C8Str>> {
        self.inner.credential_disclaimer(cred)
    }

    fn credential_warning<'b>(&'b self, cred: &Self::CredentialRef) -> Option<Cow<'b, C8Str>> {
        self.inner.credential_warning(cred)
    }

    fn get_credential_field_label<'b>(
        &'b self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'b, C8Str>> {
        self.inner.get_credential_field_label(cred, path)
    }

    fn get_credential_field_value<'b>(
        &'b self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
    ) -> Option<Cow<'b, C8Str>> {
        self.inner.get_credential_field_value(cred, path)
    }

    fn supports_protocol(&self, cred: &Self::CredentialRef, protocol: &str) -> bool {
        self.inner.supports_protocol(cred, protocol)
    }

    fn openid4vp_config(&self) -> dcapi_matcher::OpenId4VpConfig {
        self.config
    }

    fn locales(&self) -> &[&str] {
        self.inner.locales()
    }
}

fn entry_metadata<'a>(entry: &'a CredentialEntry<'a>) -> Option<&'a CStr> {
    match entry {
        CredentialEntry::StringId(entry) => entry.metadata.as_deref(),
        CredentialEntry::Payment(entry) => entry.metadata.as_deref(),
    }
}

fn entry_cred_id<'a>(entry: &'a CredentialEntry<'a>) -> &'a CStr {
    match entry {
        CredentialEntry::StringId(entry) => &entry.cred_id,
        CredentialEntry::Payment(entry) => &entry.cred_id,
    }
}

fn entry_fields<'a>(entry: &'a CredentialEntry<'a>) -> &'a [Field<'a>] {
    match entry {
        CredentialEntry::StringId(entry) => entry.fields.as_ref(),
        CredentialEntry::Payment(entry) => entry.fields.as_ref(),
    }
}

fn collect_set_configs<'a>(response: &'a dcapi_matcher::MatcherResponse<'a>) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for result in response.results.iter() {
        if let MatcherResult::Group(set) = result {
            let mut ids = set
                .slots
                .iter()
                .filter_map(|slot| {
                    let entry = slot.alternatives.first()?;
                    Some(
                        entry_cred_id(entry)
                            .to_str()
                            .unwrap_or("")
                            .split('-')
                            .next()
                            .unwrap_or("")
                            .to_string(),
                    )
                })
                .collect::<Vec<_>>();
            ids.sort();
            out.push(ids);
        }
    }
    out
}

#[test]
fn openid4vp_dcql_generates_selection_sets() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } },
                        { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
    let configs = collect_set_configs(&response);
    assert_eq!(configs, vec![vec!["mdl".to_string(), "pid".to_string()]]);
}

#[test]
fn openid4vp_dcql_single_set_with_multiple_options_merges_alternatives() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } },
                        { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
                    ],
                    "credential_sets": [
                        { "required": true, "options": [["pid"], ["mdl"]] }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected group");
    };
    assert_eq!(set.slots.len(), 1);

    let mut alt_ids = set.slots[0]
        .alternatives
        .iter()
        .filter_map(|entry| entry_cred_id(entry).to_str().ok().map(str::to_string))
        .collect::<Vec<_>>();
    alt_ids.sort();
    assert_eq!(alt_ids, vec!["mdl-1".to_string(), "pid-1".to_string(), "pid-2".to_string()]);
}

#[test]
fn openid4vp_dcql_order_prefers_optional_presence_in_first_alternative() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } },
                        { "id": "mdl", "format": "mso_mdoc", "meta": { "doctype_value": "org.iso.18013.5.1.mDL" } }
                    ],
                    "credential_sets": [
                        { "required": true, "options": [["pid"]] },
                        { "required": false, "options": [["mdl"]] }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let configs = collect_set_configs(&response);
    assert_eq!(configs, vec![vec!["mdl".to_string(), "pid".to_string()]]);

    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected group");
    };
    let optional_slot = set
        .slots
        .iter()
        .find(|slot| {
            slot.alternatives
                .iter()
                .any(|entry| entry_cred_id(entry).to_str().ok() == Some("mdl-1"))
        })
        .expect("expected slot containing mdl credential");
    let alt_ids = optional_slot
        .alternatives
        .iter()
        .filter_map(|entry| entry_cred_id(entry).to_str().ok())
        .collect::<Vec<_>>();
    assert!(
        alt_ids.iter().any(|id| id.starts_with("__none__")),
        "expected optional slot to include __none__ alternative"
    );
    assert_eq!(
        optional_slot
            .alternatives
            .first()
            .and_then(|entry| entry_cred_id(entry).to_str().ok()),
        Some("mdl-1")
    );
}

#[test]
fn openid4vp_transaction_data_encoded_is_decoded_and_attached() {
    let store = test_store();
    let transaction_data = json!({
        "type": "payment",
        "credential_ids": ["pid"]
    });
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&transaction_data).unwrap());
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [encoded]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    let metadata = entry_metadata(first)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(metadata.contains("\"dcql_id\":\"pid\""));
    assert!(metadata.contains("\"credential_id\":\"pid-1\""));
    assert!(metadata.contains("\"transaction_data_indices\":[0]"));
}

#[test]
fn openid4vp_ts12_payment_renders_payment_entry_with_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_PAYMENT,
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-1",
                        "payee": { "name": "Example Shop", "id": "merchant-1" },
                        "currency": "EUR",
                        "amount": 42.50
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(matches!(first, CredentialEntry::Payment(_)));
    assert!(!entry_fields(first).is_empty());

    let _ = test_shim::take_display();
    response.render();
    let events = test_shim::take_display().events;
    assert!(events.iter().any(|event| matches!(
        event,
        DisplayEvent::AddPaymentEntry { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    ) || matches!(
        event,
        DisplayEvent::AddPaymentEntryToSet { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    ) || matches!(
        event,
        DisplayEvent::AddPaymentEntryToSetV2 { merchant_name, transaction_amount, .. }
            if merchant_name == "Example Shop" && transaction_amount == "42.5 EUR"
    )));
    assert!(events.iter().any(|event| matches!(
        event,
        DisplayEvent::AddFieldForStringIdEntry { display_name, .. }
            if display_name == "Transaction ID" || display_name == "name"
    ) || matches!(
        event,
        DisplayEvent::AddFieldToEntrySet { field_display_name, .. }
            if field_display_name == "Transaction ID" || field_display_name == "name"
    )));
}

#[test]
fn openid4vp_ts12_generic_requires_subtype() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_GENERIC,
                    "credential_ids": ["pid"],
                    "transaction_data_hashes_alg": "sha-256",
                    "payload": {
                        "transaction_id": "tx-login-1",
                        "challenge": "abcd"
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_ts12_generic_renders_transaction_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_GENERIC,
                    "subtype": "login",
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-login-2",
                        "channel": "mobile"
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &ts12_options()).unwrap();
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let first = &set.slots[0].alternatives[0];
    assert!(matches!(first, CredentialEntry::StringId(_)));
    assert!(!entry_fields(first).is_empty());
}

#[test]
fn openid4vp_ts12_allows_fallback_locale() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": TS12_TYPE_PAYMENT,
                    "credential_ids": ["pid"],
                    "payload": {
                        "transaction_id": "tx-1",
                        "payee": { "name": "Example Shop", "id": "merchant-1" },
                        "currency": "EUR",
                        "amount": 42.50
                    }
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn openid4vp_signed_protocol_reports_unsupported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_MULTISIGNED,
            "data": {
                "payload": "e30",
                "signatures": [{
                    "protected": "eyJhbGciOiJFUzI1NiJ9",
                    "signature": "c2lnbmF0dXJl"
                }]
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_single_signed_protocol_reports_unsupported() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_SIGNED,
            "data": { "request": "eyJhbGciOiJFUzI1NiJ9..." }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_ignores_unknown_parameters() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "unknown_top_level": "ignored"
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
}

#[test]
fn openid4vp_unsigned_request_ignores_client_identification_fields() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "client_id": "ignored-client",
                "expected_origins": ["https://verifier.example"],
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1);
}

#[test]
fn openid4vp_dcql_disabled_returns_empty() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                },
                "transaction_data": [{
                    "type": "payment",
                    "credential_ids": ["pid"]
                }]
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: false,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config,
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn openid4vp_response_mode_jwt_is_gated() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "response_mode": "dc_api.jwt",
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: true,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config,
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let wrapped = VpOverride {
        inner: &store,
        config: dcapi_matcher::OpenId4VpConfig {
            allow_response_mode_jwt: true,
            ..vp_config
        },
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(!response.results.is_empty());
}

#[test]
fn openid4vp_scope_based_dcql_is_gated() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "scope": "dcql:pid"
            }
        }]
    })
    .to_string();

    let vp_config = dcapi_matcher::OpenId4VpConfig {
        enabled: true,
        allow_dcql: true,
        allow_dcql_scope: false,
        allow_transaction_data: true,
        allow_signed_requests: false,
        allow_response_mode_jwt: false,
    };
    let wrapped = VpOverride {
        inner: &store,
        config: vp_config,
    };
    let response = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());

    let wrapped = VpOverride {
        inner: &store,
        config: dcapi_matcher::OpenId4VpConfig {
            allow_dcql_scope: true,
            ..vp_config
        },
    };
    let err = match_dc_api_request(&request, &wrapped, &MatcherOptions::default()).unwrap_err();
    assert!(matches!(err, MatcherError::InvalidOpenId4Vp(_)));
}

#[test]
fn unknown_protocol_is_ignored() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": "unknown-protocol",
            "data": {}
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert!(response.results.is_empty());
}

#[test]
fn metadata_preserves_object_key_order() {
    let store = test_store();
    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "dcql_query": {
                    "credentials": [
                        { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected set");
    };
    let metadata = entry_metadata(&set.slots[0].alternatives[0])
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let pos_credential = metadata.find("\"credential_id\"").unwrap();
    let pos_dcql = metadata.find("\"dcql_id\"").unwrap();
    let pos_indices = metadata.find("\"transaction_data_indices\"").unwrap();
    assert!(pos_credential < pos_dcql);
    assert!(pos_dcql < pos_indices);
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
struct DemoPackage {
    version: u32,
    name: String,
}

#[test]
fn openid4vp_zk_format_falls_back_to_non_zk_option() {
    let store = TestStore::new(vec![TestCredential {
        id: c8string("age-mdoc-1"),
        title: c8string("Age Credential"),
        format: CredentialFormat::MsoMdoc,
        protocols: HashSet::from(["openid4vp-v1-unsigned".to_string()]),
        vcts: vec![],
        doctype: Some("eu.europa.ec.av.1".to_string()),
        holder_binding: true,
        claims: json!({"eu.europa.ec.av.1": {"age_over_18": true}}),
        transaction_data_types: vec![],
        ts12_metadata: vec![],
    }]);

    let request = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": {
                "nonce": "test-nonce",
                "dcql_query": {
                    "credential_sets": [
                        {
                            "options": [["age_credential_zk"], ["age_credential_mdoc"]],
                            "purpose": "Age verification"
                        }
                    ],
                    "credentials": [
                        {
                            "id": "age_credential_zk",
                            "format": "mso_mdoc_zk",
                            "meta": {
                                "doctype_value": "eu.europa.ec.av.1",
                                "zk_system_type": [{
                                    "system": "longfellow-libzk-v1",
                                    "circuit_hash": "137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6",
                                    "num_attributes": 1,
                                    "version": 6,
                                    "block_enc_hash": 4096,
                                    "block_enc_sig": 2945
                                }]
                            },
                            "claims": [
                                { "path": ["eu.europa.ec.av.1", "age_over_18"] }
                            ]
                        },
                        {
                            "id": "age_credential_mdoc",
                            "format": "mso_mdoc",
                            "meta": {
                                "doctype_value": "eu.europa.ec.av.1"
                            },
                            "claims": [
                                { "path": ["eu.europa.ec.av.1", "age_over_18"] }
                            ]
                        }
                    ]
                }
            }
        }]
    })
    .to_string();

    let response = match_dc_api_request(&request, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(response.results.len(), 1, "expected exactly one result group");

    let MatcherResult::Group(set) = &response.results[0] else {
        panic!("expected group");
    };
    assert_eq!(set.slots.len(), 1, "expected one slot");

    let alt_ids: Vec<_> = set.slots[0]
        .alternatives
        .iter()
        .filter_map(|entry| entry_cred_id(entry).to_str().ok())
        .collect();
    assert_eq!(alt_ids, vec!["age-mdoc-1"], "only the non-zk mdoc credential should match");
}

#[test]
fn decode_helpers_support_json_packages() {
    let package = DemoPackage {
        version: 1,
        name: "cm-package".to_string(),
    };
    let json_bytes = serde_json::to_vec(&package).unwrap();
    let decoded_json: DemoPackage = decode_json_package(&json_bytes).unwrap();
    assert_eq!(decoded_json, package);
}

#[test]
fn openid4vp_accepts_object_and_string_data_forms() {
    let store = test_store();
    let body = json!({
        "dcql_query": {
            "credentials": [
                { "id": "pid", "format": "dc+sd-jwt", "meta": { "vct_values": ["vct:pid"] } }
            ]
        }
    });
    let request_object = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": body
        }]
    })
    .to_string();
    let request_string = json!({
        "requests": [{
            "protocol": PROTOCOL_OPENID4VP_V1_UNSIGNED,
            "data": serde_json::to_string(&body).unwrap()
        }]
    })
    .to_string();

    let a = match_dc_api_request(&request_object, &store, &MatcherOptions::default()).unwrap();
    let b = match_dc_api_request(&request_string, &store, &MatcherOptions::default()).unwrap();
    assert_eq!(a.results.len(), 1);
    assert_eq!(b.results.len(), 1);
}
