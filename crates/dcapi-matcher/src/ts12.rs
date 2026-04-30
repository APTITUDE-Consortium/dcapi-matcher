use crate::diagnostics::ErrorExt;
use crate::error::{MatcherError, Ts12Error, Ts12MetadataError};
use crate::models::Ts12DataType;
use crate::traits::{DcqlSelectionContext, MatcherStore};
use alloc::borrow::Cow;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use c8str::{C8Str, C8String};
use dcapi_dcql::{ClaimsPathPointer, PathElement, TransactionData, path_matches};
use serde_json::Value;

/// Localized label entry for TS12 claim metadata.
#[derive(Debug, Clone)]
pub struct Ts12LocalizedLabel<'a> {
    /// RFC5646 locale identifier.
    pub locale: String,
    /// Human-readable label for the field.
    pub label: Cow<'a, C8Str>,
    /// Optional description text.
    pub description: Option<Cow<'a, C8Str>>,
}

/// One claim metadata entry for TS12 transaction data.
#[derive(Debug, Clone)]
pub struct Ts12ClaimMetadata<'a> {
    /// Claims path pointer (relative to `payload`).
    pub path: ClaimsPathPointer,
    /// Localized display entries.
    pub display: Vec<Ts12LocalizedLabel<'a>>,
}

/// Localized UI label entry for TS12 UI elements.
#[derive(Debug, Clone)]
pub struct Ts12LocalizedValue<'a> {
    /// RFC5646 locale identifier.
    pub locale: String,
    /// Localized string value.
    pub value: Cow<'a, C8Str>,
}

/// TS12 UI label catalogue (preserves insertion order).
pub type Ts12UiLabels<'a> = Vec<(String, Vec<Ts12LocalizedValue<'a>>)>;

/// Resolved TS12 transaction metadata for one transaction data type.
#[derive(Debug, Clone)]
pub struct Ts12TransactionMetadata<'a> {
    /// Transaction data type and optional subtype this metadata applies to.
    pub data_type: Ts12DataType,
    /// Claim metadata entries for the transaction payload.
    pub claims: Vec<Ts12ClaimMetadata<'a>>,
    /// Localised UI labels for transaction confirmation UI elements.
    pub ui_labels: Ts12UiLabels<'a>,
}

/// Payment rendering summary for TS12 flows.
#[derive(Debug, Clone)]
pub struct Ts12PaymentSummary<'a> {
    /// Merchant/payee name shown in payment UI.
    pub merchant_name: Cow<'a, C8Str>,
    /// Transaction amount string shown in payment UI.
    pub transaction_amount: Cow<'a, C8Str>,
    /// Optional extra context for payment UI.
    pub additional_info: Option<Cow<'a, C8Str>>,
}

/// Display payload for one credential selection containing TS12 transaction data.
#[derive(Debug, Clone)]
pub(crate) struct Ts12Display<'a> {
    pub transaction_fields: Vec<Ts12DisplayField<'a>>,
    pub payment_summary: Option<Ts12PaymentSummary<'a>>,
}

#[derive(Debug, Clone)]
pub(crate) struct Ts12DisplayField<'a> {
    pub display_name: Cow<'a, C8Str>,
    pub display_value: Cow<'a, C8Str>,
}

#[derive(Debug, Clone)]
struct Ts12RenderedField {
    label: C8String,
    value: C8String,
}

#[derive(Debug, Clone)]
struct Ts12TransactionDisplay {
    locale: String,
    fields: Vec<Ts12RenderedField>,
}

/// TS12 transaction-data shape accepted by the matcher.
pub(crate) struct Ts12TransactionDataShape<'a> {
    _payload: Option<&'a Value>,
}

impl<'a> Ts12TransactionDataShape<'a> {
    pub(crate) fn build(
        index: usize,
        transaction_data: &'a TransactionData,
    ) -> Result<Self, Ts12Error> {
        let Some(payload) = transaction_data_payload(transaction_data) else {
            return Ok(Self { _payload: None });
        };

        let Value::Object(_) = payload else {
            return Err(Ts12Error::PayloadNotObject { index });
        };

        Ok(Self {
            _payload: Some(payload),
        })
    }
}

fn transaction_data_payload(transaction_data: &TransactionData) -> Option<&Value> {
    transaction_data.extra.get("payload")
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

/// Builds TS12 display output for the provided selection context.
pub(crate) fn build_display_for_context<'a, S>(
    store: &'a S,
    cred: &S::CredentialRef,
    credential_id: &C8Str,
    context: &DcqlSelectionContext<'_>,
    locales: &[&str],
) -> Result<Option<Ts12Display<'a>>, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let transaction_data = context.transaction_data;
    let transaction_data_indices = context.transaction_data_indices;

    let mut displays = Vec::new();
    let mut payment_summaries = Vec::new();

    for idx in transaction_data_indices {
        let Some(td) = transaction_data.get(*idx) else {
            continue;
        };
        let Some(payload) = transaction_data_payload(td) else {
            continue;
        };
        let Some(metadata) = store.ts12_transaction_metadata(cred, td) else {
            let err = Ts12MetadataError::MissingMetadata {
                credential_id: credential_id.as_str().to_string(),
                data_type: ts12_data_type_from_transaction_data(td),
            };
            err.warn();
            continue;
        };
        let ctx = RenderContext {
            credential_id,
            transaction_data: td,
            payload,
            metadata: &metadata,
            locales,
            store,
            cred,
        };
        let display = match render_transaction_display(&ctx) {
            Ok(display) => display,
            Err(err) => {
                err.warn();
                continue;
            }
        };
        if let Some(summary) =
            store.ts12_payment_summary(cred, td, payload, &metadata, &display.locale)
        {
            payment_summaries.push(summary);
        }
        displays.push(display);
    }

    if displays.is_empty() {
        return Ok(None);
    }

    let transaction_fields = displays
        .iter()
        .flat_map(|display| {
            display.fields.iter().map(|field| Ts12DisplayField {
                display_name: Cow::Owned(field.label.clone()),
                display_value: Cow::Owned(field.value.clone()),
            })
        })
        .collect::<Vec<_>>();

    let payment_summary = if displays.len() == 1 && payment_summaries.len() == 1 {
        Some(payment_summaries.remove(0))
    } else {
        None
    };

    Ok(Some(Ts12Display {
        transaction_fields,
        payment_summary,
    }))
}

struct RenderContext<'a, S: MatcherStore + ?Sized> {
    credential_id: &'a C8Str,
    transaction_data: &'a TransactionData,
    payload: &'a Value,
    metadata: &'a Ts12TransactionMetadata<'a>,
    locales: &'a [&'a str],
    store: &'a S,
    cred: &'a S::CredentialRef,
}

fn render_transaction_display<S>(
    ctx: &RenderContext<'_, S>,
) -> Result<Ts12TransactionDisplay, Ts12MetadataError>
where
    S: MatcherStore + ?Sized,
{
    let data_type = ts12_data_type_from_transaction_data(ctx.transaction_data);
    if ctx.metadata.data_type != data_type {
        return Err(Ts12MetadataError::MetadataTypeMismatch {
            credential_id: ctx.credential_id.as_str().to_string(),
            expected: ctx.metadata.data_type.clone(),
            actual: data_type,
        });
    }
    let mut fields = Vec::new();
    let mut collected = Vec::new();
    let mut path = vec![PathElement::String("payload".to_string())];
    collect_payload_fields(&mut path, ctx.payload, &mut collected);

    let mut used_claims = Vec::new();
    for (path, value) in &collected {
        let Some(claim) = find_claim_metadata(&ctx.metadata.claims, path) else {
            continue;
        };
        used_claims.push((path.clone(), value.clone(), claim));
    }

    let locale = select_locale(
        ctx.credential_id,
        &ctx.metadata.data_type,
        ctx.locales,
        &used_claims,
        &ctx.metadata.ui_labels,
    )?;

    ui_labels_for_locale(
        ctx.credential_id,
        &ctx.metadata.data_type,
        &ctx.metadata.ui_labels,
        &locale,
    )?;

    for (path, value, claim) in used_claims {
        let display = match_localized_label(&locale, &claim.display).ok_or_else(|| {
            Ts12MetadataError::MissingClaimLabel {
                credential_id: ctx.credential_id.as_str().to_string(),
                data_type: ctx.metadata.data_type.clone(),
                locale: locale.clone(),
                path: path.clone(),
            }
        })?;
        if display.label.as_bytes().is_empty() {
            return Err(Ts12MetadataError::EmptyClaimLabel {
                credential_id: ctx.credential_id.as_str().to_string(),
                data_type: ctx.metadata.data_type.clone(),
                locale: locale.clone(),
                path: path.clone(),
            });
        }
        let formatted = ctx
            .store
            .format_ts12_value(ctx.cred, &path, &value, &locale)
            .map(cow_to_c8string)
            .unwrap_or_else(|| format_value(&value));
        fields.push(Ts12RenderedField {
            label: cow_to_c8string(display.label.clone()),
            value: formatted,
        });
    }

    Ok(Ts12TransactionDisplay { locale, fields })
}

fn collect_payload_fields(
    path: &mut ClaimsPathPointer,
    value: &Value,
    out: &mut Vec<(ClaimsPathPointer, Value)>,
) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                path.push(PathElement::String(key.clone()));
                collect_payload_fields(path, item, out);
                path.pop();
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                path.push(PathElement::Index(idx as u64));
                collect_payload_fields(path, item, out);
                path.pop();
            }
        }
        _ => out.push((path.clone(), value.clone())),
    }
}

fn find_claim_metadata<'a>(
    claims: &'a [Ts12ClaimMetadata<'a>],
    path: &ClaimsPathPointer,
) -> Option<&'a Ts12ClaimMetadata<'a>> {
    if let Some(found) = claims.iter().find(|claim| claim.path == *path) {
        return Some(found);
    }
    claims.iter().find(|claim| path_matches(&claim.path, path))
}

fn select_locale(
    credential_id: &C8Str,
    data_type: &Ts12DataType,
    locales: &[&str],
    used_claims: &[(ClaimsPathPointer, Value, &Ts12ClaimMetadata<'_>)],
    ui_labels: &Ts12UiLabels<'_>,
) -> Result<String, Ts12MetadataError> {
    let Some(affirmative_labels) = ui_labels_entry(ui_labels, "affirmative_action_label") else {
        return Err(Ts12MetadataError::MissingUiLabels {
            credential_id: credential_id.as_str().to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
        });
    };

    let candidates = if locales.is_empty() {
        fallback_locales(affirmative_labels)
    } else {
        locales.iter().map(|value| (*value).to_string()).collect()
    };

    if candidates.is_empty() {
        return Err(Ts12MetadataError::MissingPreferredLocales {
            credential_id: credential_id.as_str().to_string(),
            data_type: data_type.clone(),
        });
    }

    let mut missing_claim_label = None;
    let mut missing_ui_label = true;

    for locale in &candidates {
        let ui_ok = match_localized_value(locale, affirmative_labels).is_some();
        if ui_ok {
            missing_ui_label = false;
        }
        let mut missing_path = None;
        for (path, _, claim) in used_claims {
            if match_localized_label(locale, &claim.display).is_none() {
                missing_path = Some(path.clone());
                break;
            }
        }
        if ui_ok && missing_path.is_none() {
            return Ok(locale.clone());
        }
        if missing_claim_label.is_none() {
            let Some(missing_path) = missing_path else {
                continue;
            };
            missing_claim_label = Some(Ts12MetadataError::MissingClaimLabel {
                credential_id: credential_id.as_str().to_string(),
                data_type: data_type.clone(),
                locale: locale.clone(),
                path: missing_path,
            });
        }
    }

    let Some(first_locale) = candidates.first().cloned() else {
        return Err(Ts12MetadataError::MissingPreferredLocales {
            credential_id: credential_id.as_str().to_string(),
            data_type: data_type.clone(),
        });
    };
    if missing_ui_label {
        return Err(Ts12MetadataError::MissingLocalizedUiLabel {
            credential_id: credential_id.as_str().to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
            locale: first_locale.clone(),
        });
    }

    if let Some(err) = missing_claim_label {
        return Err(err);
    }

    Err(Ts12MetadataError::MissingLocalizedUiLabel {
        credential_id: credential_id.as_str().to_string(),
        data_type: data_type.clone(),
        label: "affirmative_action_label",
        locale: first_locale,
    })
}

fn fallback_locales(labels: &[Ts12LocalizedValue<'_>]) -> Vec<String> {
    let mut locales = Vec::new();
    for entry in labels {
        if locales.iter().any(|existing| existing == &entry.locale) {
            continue;
        }
        locales.push(entry.locale.clone());
    }
    locales
}

fn ui_labels_for_locale(
    credential_id: &C8Str,
    data_type: &Ts12DataType,
    ui_labels: &Ts12UiLabels<'_>,
    locale: &str,
) -> Result<(), Ts12MetadataError> {
    if !ui_labels.iter().any(|(key, values)| {
        key == "affirmative_action_label" && match_localized_value(locale, values).is_some()
    }) {
        return Err(Ts12MetadataError::MissingLocalizedUiLabel {
            credential_id: credential_id.as_str().to_string(),
            data_type: data_type.clone(),
            label: "affirmative_action_label",
            locale: locale.to_string(),
        });
    }
    Ok(())
}

fn ui_labels_entry<'a>(
    ui_labels: &'a Ts12UiLabels<'a>,
    key: &str,
) -> Option<&'a [Ts12LocalizedValue<'a>]> {
    ui_labels
        .iter()
        .find(|(label_key, _)| label_key == key)
        .map(|(_, values)| values.as_slice())
}

fn match_localized_label<'a>(
    preferred: &str,
    labels: &'a [Ts12LocalizedLabel<'a>],
) -> Option<&'a Ts12LocalizedLabel<'a>> {
    let preferred = canonical_locale(preferred);
    let preferred_primary = primary_locale(&preferred);
    labels
        .iter()
        .find(|label| canonical_locale(&label.locale) == preferred)
        .or_else(|| {
            labels
                .iter()
                .find(|label| primary_locale(&canonical_locale(&label.locale)) == preferred_primary)
        })
}

fn match_localized_value<'a>(
    preferred: &str,
    values: &'a [Ts12LocalizedValue<'a>],
) -> Option<&'a Ts12LocalizedValue<'a>> {
    let preferred = canonical_locale(preferred);
    let preferred_primary = primary_locale(&preferred);
    values
        .iter()
        .find(|value| canonical_locale(&value.locale) == preferred)
        .or_else(|| {
            values
                .iter()
                .find(|value| primary_locale(&canonical_locale(&value.locale)) == preferred_primary)
        })
}

fn canonical_locale(value: &str) -> String {
    value.trim().replace('_', "-").to_ascii_lowercase()
}

fn primary_locale(value: &str) -> &str {
    value.split('-').next().unwrap_or(value)
}

fn cow_to_c8string(value: Cow<'_, C8Str>) -> C8String {
    value.into_owned()
}

fn format_value(value: &Value) -> C8String {
    let mut bytes = match value {
        Value::String(v) => v.as_bytes().to_vec(),
        Value::Number(v) => v.to_string().into_bytes(),
        Value::Bool(v) => v.to_string().into_bytes(),
        Value::Null => Vec::new(),
        Value::Array(_) | Value::Object(_) => value.to_string().into_bytes(),
    };
    bytes.retain(|byte| *byte != 0);
    C8String::from_vec(bytes).unwrap_or_else(|_| C8String::new())
}
