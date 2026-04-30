use crate::diagnostics::ErrorExt;
use crate::error::{MatcherError, Ts12Error, Ts12MetadataError};
use crate::models::Ts12DataType;
use crate::traits::{DcqlSelectionContext, MatcherStore};
use alloc::borrow::Cow;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use c8str::C8Str;
use dcapi_dcql::{ClaimsPathPointer, PathElement, TransactionData, select_nodes};
use serde_json::Value;

/// One claim metadata entry for TS12 transaction data.
#[derive(Debug, Clone)]
pub struct Ts12ClaimMetadata {
    /// Claims path pointer (relative to `payload`).
    pub path: ClaimsPathPointer,
    /// Whether this claim must be present in the transaction payload.
    pub mandatory: bool,
    /// Optional value formatter for displayable claim values.
    pub value_type: Option<String>,
    /// Whether the claim has TS12 display metadata.
    pub displayable: bool,
}

/// Resolved TS12 transaction metadata for one transaction data type.
#[derive(Debug, Clone)]
pub struct Ts12TransactionMetadata {
    /// Transaction data type this metadata applies to.
    pub data_type: Ts12DataType,
    /// Claim metadata entries for the transaction payload.
    pub claims: Vec<Ts12ClaimMetadata>,
}

impl Ts12TransactionMetadata {
    /// Returns true when `payload` conforms to the metadata constraints used for TS12 matching.
    pub fn is_payload_compatible(&self, payload: &Value) -> bool {
        let Value::Object(_) = payload else {
            return false;
        };

        let mut payload_paths = Vec::new();
        let mut path = Vec::new();
        collect_payload_paths(&mut path, payload, &mut payload_paths);

        if payload_paths.iter().any(|path| {
            !self
                .claims
                .iter()
                .any(|claim| dcapi_dcql::path_matches(&claim.path, path))
        }) {
            return false;
        }

        for claim in &self.claims {
            if !claim.displayable {
                if claim.value_type.is_some() {
                    return false;
                }
                continue;
            }

            let Some(value_type) = claim.value_type.as_deref() else {
                match claim_values(payload, &claim.path) {
                    Some(values) if values.iter().all(|value| value.is_string()) => continue,
                    None if !claim.mandatory => continue,
                    _ => return false,
                }
            };

            if !is_supported_value_type(value_type) {
                return false;
            }
            if value_type == "label_only" && claim.mandatory {
                return false;
            }
            let Some(values) = claim_values(payload, &claim.path) else {
                if claim.mandatory {
                    return false;
                }
                continue;
            };
            if !values
                .iter()
                .all(|value| value_conforms_to_type(value, value_type))
            {
                return false;
            }
            if value_type == "image"
                && values.iter().any(|value| {
                    image_requires_integrity(value) && !has_integrity_sibling(payload, &claim.path)
                })
            {
                return false;
            }
        }

        self.claims
            .iter()
            .filter(|claim| claim.mandatory)
            .all(|claim| {
                claim_values(payload, &claim.path).is_some_and(|values| !values.is_empty())
            })
    }
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
    pub payment_summary: Ts12PaymentSummary<'a>,
    pub displayed_transaction_data_index: usize,
}

/// TS12 transaction-data shape accepted by the matcher.
pub(crate) struct Ts12TransactionDataShape;

impl Ts12TransactionDataShape {
    pub(crate) fn build(
        index: usize,
        transaction_data: &TransactionData,
    ) -> Result<Self, Ts12Error> {
        let Some(payload) = transaction_data_payload(transaction_data) else {
            return Ok(Self);
        };

        let Value::Object(_) = payload else {
            return Err(Ts12Error::PayloadNotObject { index });
        };

        Ok(Self)
    }
}

fn transaction_data_payload(transaction_data: &TransactionData) -> Option<&Value> {
    transaction_data.extra.get("payload")
}

fn ts12_data_type_from_transaction_data(transaction_data: &TransactionData) -> Ts12DataType {
    Ts12DataType {
        r#type: transaction_data.r#type.clone(),
    }
}

/// Builds TS12 display output for the provided selection context.
pub(crate) fn build_display_for_context<'a, S>(
    store: &'a S,
    cred: &S::CredentialRef,
    credential_id: &C8Str,
    context: &DcqlSelectionContext<'_>,
) -> Result<Option<Ts12Display<'a>>, MatcherError>
where
    S: MatcherStore + ?Sized,
{
    let transaction_data = context.transaction_data;
    let transaction_data_indices = context.transaction_data_indices;

    let mut payment_display = None;

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
        let data_type = ts12_data_type_from_transaction_data(td);
        if metadata.data_type != data_type {
            let err = Ts12MetadataError::MetadataTypeMismatch {
                credential_id: credential_id.as_str().to_string(),
                expected: metadata.data_type.clone(),
                actual: data_type,
            };
            err.warn();
            continue;
        }
        if let Some(summary) = store.ts12_payment_summary(cred, td, payload, &metadata)
            && payment_display.replace((*idx, summary)).is_some()
        {
            return Ok(None);
        }
    }

    let Some((transaction_data_idx, payment_summary)) = payment_display else {
        return Ok(None);
    };

    Ok(Some(Ts12Display {
        payment_summary,
        displayed_transaction_data_index: transaction_data_idx,
    }))
}

fn collect_payload_paths(
    path: &mut ClaimsPathPointer,
    value: &Value,
    out: &mut Vec<ClaimsPathPointer>,
) {
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                path.push(PathElement::String(key.clone()));
                collect_payload_paths(path, item, out);
                path.pop();
            }
        }
        Value::Array(arr) => {
            for (idx, item) in arr.iter().enumerate() {
                path.push(PathElement::Index(idx as u64));
                collect_payload_paths(path, item, out);
                path.pop();
            }
        }
        _ => out.push(path.clone()),
    }
}

fn claim_values<'a>(payload: &'a Value, path: &ClaimsPathPointer) -> Option<Vec<&'a Value>> {
    select_nodes(payload, path)
        .ok()
        .filter(|values| !values.is_empty())
}

fn is_supported_value_type(value_type: &str) -> bool {
    matches!(
        value_type,
        "boolean"
            | "frequency"
            | "image"
            | "iso_date"
            | "iso_time"
            | "iso_date_time"
            | "iso_currency"
            | "iso_currency_amount"
            | "label_only"
            | "mini_markdown"
            | "url"
    )
}

fn value_conforms_to_type(value: &Value, value_type: &str) -> bool {
    match value_type {
        "boolean" => value.is_boolean(),
        "frequency" => value.as_str().is_some_and(is_frequency_code),
        "image" | "mini_markdown" | "url" => value.is_string(),
        "iso_date" => value.as_str().is_some_and(is_iso_date),
        "iso_time" => value.as_str().is_some_and(is_iso_time),
        "iso_date_time" => value.as_str().is_some_and(is_iso_date_time),
        "iso_currency" => value.as_str().is_some_and(is_iso_currency),
        "iso_currency_amount" => value.as_str().is_some_and(is_iso_currency_amount),
        "label_only" => true,
        _ => false,
    }
}

fn is_frequency_code(value: &str) -> bool {
    matches!(
        value,
        "INDA"
            | "DAIL"
            | "WEEK"
            | "TOWK"
            | "TWMN"
            | "MNTH"
            | "TOMN"
            | "QUTR"
            | "FOMN"
            | "SEMI"
            | "YEAR"
            | "TYEA"
    )
}

fn is_iso_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn is_iso_currency_amount(value: &str) -> bool {
    let Some((amount, currency)) = value.rsplit_once(' ') else {
        return false;
    };
    is_decimal_amount(amount) && is_iso_currency(currency)
}

fn is_decimal_amount(value: &str) -> bool {
    let Some((major, minor)) = value.split_once('.') else {
        return !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit());
    };
    !major.is_empty()
        && !minor.is_empty()
        && major.bytes().all(|byte| byte.is_ascii_digit())
        && minor.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(idx, byte)| matches!(idx, 4 | 7) || byte.is_ascii_digit())
}

fn is_iso_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 5
        && bytes[2] == b':'
        && bytes
            .iter()
            .take(5)
            .enumerate()
            .all(|(idx, byte)| idx == 2 || byte.is_ascii_digit())
}

fn is_iso_date_time(value: &str) -> bool {
    value
        .split_once('T')
        .is_some_and(|(date, time)| is_iso_date(date) && is_iso_time(time))
}

fn image_requires_integrity(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|text| !text.starts_with("data:") && !text.is_empty())
}

fn has_integrity_sibling(payload: &Value, path: &ClaimsPathPointer) -> bool {
    let Some((PathElement::String(last), prefix)) = path.split_last() else {
        return false;
    };
    let mut integrity_path = prefix.to_vec();
    integrity_path.push(PathElement::String(format!("{last}#integrity")));
    claim_values(payload, &integrity_path).is_some_and(|values| {
        values
            .iter()
            .all(|value| value.as_str().is_some_and(|text| !text.is_empty()))
    })
}
