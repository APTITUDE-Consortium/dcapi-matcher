use crate::config::{
    OpenId4VpConfig, QUERY_METHOD_DCQL_QUERY, REQUEST_PARAMETER_TRANSACTION_DATA,
    RESPONSE_MODE_DC_API,
};
use crate::diagnostics::{self, ErrorExt};
use crate::error::{MatcherError, OpenId4VpError, RequestDataError, TransactionDataDecodeError};
use crate::models::{
    DcApiRequest, DcApiRequestItem, OpenId4VpMultiSignedData, OpenId4VpRequest,
    OpenId4VpSignedData, OpenId4VpSignedEnvelope, OpenId4VpSignedFormat, OpenId4VpSignedSignature,
    OpenId4VpUnsignedData, PROTOCOL_OPENID4VP, PROTOCOL_OPENID4VP_V1_MULTISIGNED,
    PROTOCOL_OPENID4VP_V1_SIGNED, PROTOCOL_OPENID4VP_V1_UNSIGNED, RequestData,
    TransactionDataInput,
};
use crate::traits::{DcqlSelectionContext, MatcherStore};
use crate::ts12;
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use android_credman::{
    CredentialEntry, CredentialSet, CredentialSlot, Field, MatcherResponse, PaymentEntry,
    StringIdEntry,
};
use android_credman::{get_calling_app_info, get_request_string};
use base64::Engine;
use c8str::{C8Str, C8String, c8format};
use core::ffi::CStr;
use core::hash::Hash;
use dcapi_dcql::{PathElement, PlanOptions, SetAlternative, TransactionData};
use serde::de::DeserializeOwned;
use serde_json::Value;

/// Matcher framework options.
#[derive(Debug, Clone, Default)]
pub struct MatcherOptions {
    /// DCQL planner behavior.
    pub dcql: PlanOptions,
}

/// Parses and matches the DC API request from the Credman host.
pub fn match_dc_api_request<'a, S>(
    store: &'a S,
    options: &MatcherOptions,
) -> Result<MatcherResponse<'a>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    diagnostics::begin();
    diagnostics::set_level(store.log_level());
    let request_json = get_request_string();
    let request: DcApiRequest = match serde_json::from_str(&request_json) {
        Ok(request) => request,
        Err(err) => {
            let error = MatcherError::InvalidRequestJson(err);
            error.error();
            return Err(error);
        }
    };
    let result = match_dc_api_request_value_impl(&request, store, options);
    if let Err(err) = &result {
        err.error();
    }
    result
}

fn match_dc_api_request_value_impl<'a, S>(
    request: &DcApiRequest,
    store: &'a S,
    options: &MatcherOptions,
) -> Result<MatcherResponse<'a>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let vp_config = store.openid4vp_config();
    let mut response = MatcherResponse::new();

    for (request_index, item) in request.requests.iter().enumerate() {
        match item {
            DcApiRequestItem::OpenId4VpUnsigned { data } => {
                if !vp_config.enabled
                    || !vp_config.supports_request_protocol(PROTOCOL_OPENID4VP_V1_UNSIGNED)
                {
                    continue;
                }
                let request = decode_openid4vp_unsigned_data(data)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_UNSIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::OpenId4VpSigned { data } => {
                if !vp_config.enabled
                    || !vp_config.supports_request_protocol(PROTOCOL_OPENID4VP_V1_SIGNED)
                {
                    continue;
                }
                let envelope =
                    decode_openid4vp_signed_envelope(PROTOCOL_OPENID4VP_V1_SIGNED, data)?;
                ensure_signed_request_verified(store, PROTOCOL_OPENID4VP_V1_SIGNED, &envelope)?;
                let request =
                    decode_openid4vp_request_from_payload(PROTOCOL_OPENID4VP_V1_SIGNED, &envelope)?;
                ensure_expected_origins(PROTOCOL_OPENID4VP_V1_SIGNED, &request)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_SIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::OpenId4VpMultiSigned { data } => {
                if !vp_config.enabled
                    || !vp_config.supports_request_protocol(PROTOCOL_OPENID4VP_V1_MULTISIGNED)
                {
                    continue;
                }
                let envelope =
                    decode_openid4vp_multisigned_envelope(PROTOCOL_OPENID4VP_V1_MULTISIGNED, data)?;
                ensure_signed_request_verified(
                    store,
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    &envelope,
                )?;
                let request = decode_openid4vp_request_from_payload(
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    &envelope,
                )?;
                ensure_expected_origins(PROTOCOL_OPENID4VP_V1_MULTISIGNED, &request)?;
                let result = match_openid4vp_request(
                    request_index,
                    PROTOCOL_OPENID4VP_V1_MULTISIGNED,
                    request,
                    store,
                    &vp_config,
                    options,
                );
                match result {
                    Ok(result) => {
                        response = response.add_results(result.results.into_owned());
                    }
                    Err(err) => return Err(err),
                }
            }
            DcApiRequestItem::Unknown => {}
        }
    }

    Ok(response)
}

fn decode_openid4vp_unsigned_data(
    data: &OpenId4VpUnsignedData,
) -> Result<OpenId4VpRequest, MatcherError> {
    match data {
        OpenId4VpUnsignedData::Params(request) => Ok(request.clone()),
        OpenId4VpUnsignedData::JsonString(raw) => serde_json::from_str(raw)
            .map_err(|err| MatcherError::InvalidOpenId4Vp(OpenId4VpError::Json { source: err })),
    }
}

fn decode_openid4vp_signed_envelope(
    protocol: &str,
    data: &OpenId4VpSignedData,
) -> Result<OpenId4VpSignedEnvelope, MatcherError> {
    let mut parts = data.request.split('.');
    let header_b64 = parts.next().unwrap_or_default();
    let payload_b64 = parts.next().unwrap_or_default();
    let signature_b64 = parts.next().unwrap_or_default();
    if header_b64.is_empty() || payload_b64.is_empty() || signature_b64.is_empty() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    if parts.next().is_some() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    let protected = decode_base64url_json(protocol, header_b64)?;
    let payload = decode_base64url_json(protocol, payload_b64)?;
    Ok(OpenId4VpSignedEnvelope {
        format: OpenId4VpSignedFormat::Compact,
        payload_b64: payload_b64.to_string(),
        payload,
        signatures: vec![OpenId4VpSignedSignature {
            protected_b64: header_b64.to_string(),
            protected,
            signature_b64: signature_b64.to_string(),
            header: None,
        }],
    })
}

fn decode_openid4vp_multisigned_envelope(
    protocol: &str,
    data: &OpenId4VpMultiSignedData,
) -> Result<OpenId4VpSignedEnvelope, MatcherError> {
    if data.signatures.is_empty() {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestMalformed {
                protocol: protocol.to_string(),
            },
        ));
    }
    let payload = decode_base64url_json(protocol, data.payload.as_str())?;
    let mut signatures = Vec::with_capacity(data.signatures.len());
    for signature in &data.signatures {
        if signature.protected.is_empty() || signature.signature.is_empty() {
            return Err(MatcherError::InvalidOpenId4Vp(
                OpenId4VpError::SignedRequestMalformed {
                    protocol: protocol.to_string(),
                },
            ));
        }
        let protected = decode_base64url_json(protocol, signature.protected.as_str())?;
        signatures.push(OpenId4VpSignedSignature {
            protected_b64: signature.protected.clone(),
            protected,
            signature_b64: signature.signature.clone(),
            header: signature.header.clone(),
        });
    }
    Ok(OpenId4VpSignedEnvelope {
        format: OpenId4VpSignedFormat::Json,
        payload_b64: data.payload.clone(),
        payload,
        signatures,
    })
}

fn decode_openid4vp_request_from_payload(
    protocol: &str,
    envelope: &OpenId4VpSignedEnvelope,
) -> Result<OpenId4VpRequest, MatcherError> {
    serde_json::from_value(envelope.payload.clone()).map_err(|err| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
            protocol: protocol.to_string(),
            source: err,
        })
    })
}

fn ensure_signed_request_verified<S: MatcherStore>(
    store: &S,
    protocol: &str,
    envelope: &OpenId4VpSignedEnvelope,
) -> Result<(), MatcherError> {
    if !store.verify_openid4vp_signed_request(protocol, envelope) {
        return Err(MatcherError::InvalidOpenId4Vp(
            OpenId4VpError::SignedRequestUnverified {
                protocol: protocol.to_string(),
            },
        ));
    }
    Ok(())
}

fn ensure_expected_origins(protocol: &str, request: &OpenId4VpRequest) -> Result<(), MatcherError> {
    let expected = expected_origins_from_request(request).ok_or_else(|| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::ExpectedOriginsMissing {
            protocol: protocol.to_string(),
        })
    })?;
    let origin = calling_origin().ok_or_else(|| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::OriginMissing {
            protocol: protocol.to_string(),
        })
    })?;
    if expected.iter().any(|value| value == &origin) {
        return Ok(());
    }
    Err(MatcherError::InvalidOpenId4Vp(
        OpenId4VpError::OriginMismatch {
            protocol: protocol.to_string(),
            origin,
        },
    ))
}

fn expected_origins_from_request(request: &OpenId4VpRequest) -> Option<Vec<String>> {
    let value = request.extra.get("expected_origins")?;
    let origins = value.as_array()?;
    if origins.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(origins.len());
    for entry in origins {
        let entry = entry.as_str()?;
        if entry.is_empty() {
            return None;
        }
        out.push(entry.to_string());
    }
    Some(out)
}

fn calling_origin() -> Option<String> {
    let app_info = get_calling_app_info();
    let origin = app_info.origin();
    if origin.is_empty() {
        None
    } else {
        Some(origin.to_string())
    }
}

fn decode_base64url_json(protocol: &str, input: &str) -> Result<Value, MatcherError> {
    let decoded = decode_base64url(input).map_err(MatcherError::InvalidBase64)?;
    serde_json::from_slice(&decoded).map_err(|err| {
        MatcherError::InvalidOpenId4Vp(OpenId4VpError::SignedPayloadNotSupported {
            protocol: protocol.to_string(),
            source: err,
        })
    })
}

fn match_openid4vp_request<'s, S>(
    request_index: usize,
    protocol: &str,
    mut request: OpenId4VpRequest,
    store: &'s S,
    config: &OpenId4VpConfig,
    options: &MatcherOptions,
) -> Result<MatcherResponse<'s>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let mut response = MatcherResponse::new();

    let response_mode = request
        .response_mode
        .as_deref()
        .unwrap_or(RESPONSE_MODE_DC_API);
    if !config.supports_response_mode(response_mode) {
        return Ok(response);
    }

    if let Some(response_type) = request.response_type.as_deref()
        && !config.supports_response_type(response_type)
    {
        return Ok(response);
    }

    let dcql_query = match request.dcql_query.take() {
        Some(dcql_query) => {
            if !config.supports_query_method(QUERY_METHOD_DCQL_QUERY) {
                return Ok(response);
            }
            dcql_query
        }
        None => return Ok(response),
    };

    let transaction_data = decode_transaction_data(request.transaction_data.as_deref());
    if transaction_data
        .as_ref()
        .is_some_and(|data| !data.is_empty())
        && !config.supports_request_parameter(REQUEST_PARAMETER_TRANSACTION_DATA)
    {
        return Ok(response);
    }
    let plan = match dcapi_dcql::plan_selection(
        &dcql_query,
        transaction_data.as_deref(),
        store,
        &options.dcql,
    ) {
        Ok(plan) => plan,
        Err(dcapi_dcql::PlanError::Unsatisfied) => {
            diagnostics::warn("dcql query unsatisfied; no matching credentials");
            return Ok(response);
        }
        Err(err) => return Err(MatcherError::Dcql(err)),
    };
    for (set_index, presentation_set) in plan.presentation_sets.iter().enumerate() {
        let set = set_from_dcql_presentation_set(
            store,
            request_index,
            set_index,
            presentation_set,
            transaction_data.as_deref().unwrap_or_default(),
            protocol,
        )?;
        response = response.add_group(set);
    }
    Ok(response)
}

fn set_from_dcql_presentation_set<'s, 't, S>(
    store: &'s S,
    request_index: usize,
    set_index: usize,
    presentation_set: &'t [SetAlternative<S::CredentialRef>],
    transaction_data: &'t [TransactionData],
    protocol: &str,
) -> Result<CredentialSet<'s>, MatcherError>
where
    S: MatcherStore,
    S::CredentialRef: Clone + Eq + Hash,
{
    let set_id = cow_cstr_from_c8string(set_id_for_dcql(protocol, request_index, set_index));
    let mut set = CredentialSet::new_cow(set_id);

    for (slot_index, slot) in presentation_set.iter().enumerate() {
        let mut alternatives: Vec<CredentialEntry<'s>> = Vec::new();
        for selection in &slot.alternatives {
            let Some(cred) = &selection.credential_id else {
                alternatives.push(build_none_entry(
                    request_index,
                    set_index,
                    slot_index,
                    selection.dcql_id.as_str(),
                )?);
                continue;
            };
            if !supports_protocol(store, cred, protocol) {
                continue;
            }
            let context = DcqlSelectionContext {
                query_id: selection.dcql_id.as_str(),
                selected_claims: selection.selected_claims.as_slice(),
                transaction_data,
                transaction_data_indices: selection.transaction_data_ids.as_slice(),
            };
            match build_entry(store, cred, &context) {
                Ok(entry) => alternatives.push(entry),
                Err(err) => err.error(),
            }
        }

        if alternatives.is_empty() {
            continue;
        }
        let slot = CredentialSlot::new(alternatives);
        set = set.add_slot(slot);
    }

    Ok(set)
}

fn build_none_entry<'s>(
    request_index: usize,
    set_index: usize,
    slot_index: usize,
    dcql_id: &str,
) -> Result<CredentialEntry<'s>, MatcherError> {
    let cred_id = cow_cstr_from_c8string(c8format!(
        "__none__:{request_index}:{set_index}:{slot_index}"
    ));
    let title = cow_cstr_from_bytes("No credential");
    let mut entry = StringIdEntry::new_cow(cred_id, title);
    entry.metadata = build_metadata(dcql_id, "__none__", None)?;
    entry.fields = Cow::Owned(vec![Field::from_cow(
        cow_cstr_from_bytes("No credential will be presented"),
        None,
    )]);
    Ok(CredentialEntry::StringId(entry))
}

fn supports_protocol<S: MatcherStore>(store: &S, cred: &S::CredentialRef, protocol: &str) -> bool {
    if store.supports_protocol(cred, protocol) {
        return true;
    }
    if protocol == PROTOCOL_OPENID4VP_V1_UNSIGNED {
        return store.supports_protocol(cred, PROTOCOL_OPENID4VP);
    }
    if protocol == PROTOCOL_OPENID4VP {
        return store.supports_protocol(cred, PROTOCOL_OPENID4VP_V1_UNSIGNED);
    }
    false
}

fn build_entry<'s, 'c, S>(
    store: &'s S,
    cred: &S::CredentialRef,
    context: &DcqlSelectionContext<'c>,
) -> Result<CredentialEntry<'s>, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let credential_id = store.credential_id(cred);
    let title = store.credential_title(cred);
    let icon = store.credential_icon(cred);
    let subtitle = store.credential_subtitle(cred);
    let disclaimer = store.credential_disclaimer(cred);
    let warning = store.credential_warning(cred);
    let ts12_display =
        ts12::build_display_for_context(store, cred, credential_id.as_ref(), context)?;
    let (payment_summary, displayed_transaction_data_index) = match ts12_display {
        Some(display) => (
            Some(display.payment_summary),
            Some(display.displayed_transaction_data_index),
        ),
        None => (None, None),
    };

    let mut fields = Vec::new();
    for claim in context.selected_claims {
        if claim
            .path
            .iter()
            .any(|segment| matches!(segment, PathElement::Wildcard))
        {
            continue;
        }
        let Some(label) = store.get_credential_field_label(cred, &claim.path) else {
            continue;
        };
        let value = store.get_credential_field_value(cred, &claim.path);
        fields.push(Field::from_cow(
            cow_cstr_from_cow(label),
            value.map(cow_cstr_from_cow),
        ));
    }
    let transaction_data =
        context
            .transaction_data_indices
            .first()
            .map(|idx| SelectedTransactionData {
                index: *idx,
                displayed: displayed_transaction_data_index == Some(*idx),
            });
    let metadata = build_metadata(context.query_id, credential_id.as_str(), transaction_data)?;

    let credential_id = cow_cstr_from_cow(credential_id);
    let title = cow_cstr_from_cow(title);
    let subtitle = subtitle.map(cow_cstr_from_cow);
    let disclaimer = disclaimer.map(cow_cstr_from_cow);
    let warning = warning.map(cow_cstr_from_cow);

    if let Some(summary) = payment_summary {
        let mut entry = PaymentEntry::new_cow(
            credential_id,
            cow_cstr_from_cow(summary.merchant_name),
            cow_cstr_from_cow(summary.transaction_amount),
        );
        entry.payment_method_name = Some(title);
        entry.payment_method_subtitle = subtitle;
        entry.payment_method_icon = icon.map(Cow::Borrowed);
        entry.additional_info = summary.additional_info.map(cow_cstr_from_cow);
        entry.metadata = metadata;
        entry.fields = Cow::Owned(fields);
        return Ok(CredentialEntry::Payment(entry));
    }

    let mut entry = StringIdEntry::new_cow(credential_id, title);
    entry.icon = icon.map(Cow::Borrowed);
    entry.subtitle = subtitle;
    entry.disclaimer = disclaimer;
    entry.warning = warning;
    entry.metadata = metadata;
    entry.fields = Cow::Owned(fields);

    Ok(CredentialEntry::StringId(entry))
}

fn build_metadata<'a>(
    dcql_id: &str,
    credential_id: &str,
    transaction_data: Option<SelectedTransactionData>,
) -> Result<Option<Cow<'a, CStr>>, MatcherError> {
    let mut obj = serde_json::Map::new();
    obj.insert("dcql_id".to_string(), Value::String(dcql_id.to_string()));
    obj.insert(
        "credential_id".to_string(),
        Value::String(credential_id.to_string()),
    );
    if let Some(transaction_data) = transaction_data {
        obj.insert("transaction_data".to_string(), transaction_data.into());
    }
    let value = Value::Object(obj);
    let bytes = serde_json::to_vec(&value)
        .map_err(|err| MatcherError::MetadataSerialization { source: err })?;
    Ok(Some(cow_cstr_from_bytes(bytes)))
}

#[derive(Debug, Clone, Copy)]
struct SelectedTransactionData {
    index: usize,
    displayed: bool,
}

impl From<SelectedTransactionData> for Value {
    fn from(transaction_data: SelectedTransactionData) -> Self {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "index".to_string(),
            Value::from(transaction_data.index as u64),
        );
        obj.insert(
            "displayed".to_string(),
            Value::Bool(transaction_data.displayed),
        );
        Value::Object(obj)
    }
}

fn set_id_for_dcql(protocol: &str, request_index: usize, alternative_index: usize) -> C8String {
    let protocol_sanitized;
    let protocol = if protocol.as_bytes().contains(&0) {
        protocol_sanitized = protocol.replace('\0', "");
        protocol_sanitized.as_str()
    } else {
        protocol
    };
    c8format!("{protocol}:{request_index}:dcql:{alternative_index}")
}

fn c8string_from_bytes(bytes: impl Into<Vec<u8>>) -> C8String {
    let mut bytes = bytes.into();
    bytes.retain(|byte| *byte != 0);
    C8String::from_vec(bytes).unwrap_or_else(|_| C8String::new())
}

fn cow_cstr_from_bytes<'a>(bytes: impl Into<Vec<u8>>) -> Cow<'a, CStr> {
    cow_cstr_from_c8string(c8string_from_bytes(bytes))
}

fn cow_cstr_from_cow<'a>(value: Cow<'a, C8Str>) -> Cow<'a, CStr> {
    match value {
        Cow::Borrowed(value) => Cow::Borrowed(value.as_c_str()),
        Cow::Owned(value) => cow_cstr_from_c8string(value),
    }
}

fn cow_cstr_from_c8string<'a>(value: C8String) -> Cow<'a, CStr> {
    Cow::Owned(value.into_c_string())
}

fn decode_transaction_data(
    transaction_data: Option<&[TransactionDataInput]>,
) -> Option<Vec<TransactionData>> {
    let transaction_data = transaction_data?;

    let mut out = Vec::with_capacity(transaction_data.len());
    for (index, item) in transaction_data.iter().enumerate() {
        let parsed = match item {
            TransactionDataInput::Decoded(data) => data.as_ref().clone(),
            TransactionDataInput::Encoded(encoded) => {
                let bytes = match decode_base64url(encoded) {
                    Ok(bytes) => bytes,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Base64 { index, source: err };
                        warn.warn();
                        continue;
                    }
                };
                match serde_json::from_slice::<TransactionData>(&bytes) {
                    Ok(parsed) => parsed,
                    Err(err) => {
                        let warn = TransactionDataDecodeError::Json { index, source: err };
                        warn.warn();
                        continue;
                    }
                }
            }
        };

        if parsed.r#type.is_empty() {
            let warn = TransactionDataDecodeError::MissingType { index };
            warn.warn();
            continue;
        }
        if parsed.credential_ids.is_empty() {
            let warn = TransactionDataDecodeError::MissingCredentialIds { index };
            warn.warn();
            continue;
        }
        if let Err(err) = ts12::Ts12TransactionDataShape::build(index, &parsed) {
            err.warn();
            continue;
        }

        out.push(parsed);
    }
    Some(out)
}

fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    match engine.decode(input) {
        Ok(bytes) => Ok(bytes),
        Err(_) => {
            let padded = pad_base64url(input);
            engine.decode(padded)
        }
    }
}

fn pad_base64url(input: &str) -> String {
    let remainder = input.len() % 4;
    if remainder == 0 {
        return input.to_string();
    }
    let mut out = input.to_string();
    for _ in 0..(4 - remainder) {
        out.push('=');
    }
    out
}

/// Parses JSON from `RequestData` and deserializes into a target type.
pub fn decode_request_data<T: DeserializeOwned>(data: &RequestData) -> Result<T, MatcherError> {
    let value = data
        .to_value()
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))?;
    serde_json::from_value(value)
        .map_err(|err| MatcherError::InvalidRequestData(RequestDataError::Json { source: err }))
}
