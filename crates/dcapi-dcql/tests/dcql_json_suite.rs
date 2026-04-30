use dcapi_dcql::{
    ClaimValue, CredentialFormat, CredentialStore, DEFAULT_TS12_PREFIX, DcqlOutput,
    OptionalCredentialSetsMode, PlanError, PlanOptions, TransactionData, TransactionDataType,
    TrustedAuthority, ValueMatch, plan_selection,
};
use rustc_hash::FxHashMap;
use serde::Deserialize;
use serde_json::{Map, Value, json};

macro_rules! ts12_sca_type {
    ($suffix:literal) => {
        concat!("urn:eudi:sca:", $suffix)
    };
}

const SCA_PAY_V1: &str = ts12_sca_type!("example.pay:transaction:1");
const SCA_PAY_V2: &str = ts12_sca_type!("example.pay:transaction:2");
const SCA_CARD: &str = ts12_sca_type!("example.pay:card:1");
const SCA_ACCOUNT: &str = ts12_sca_type!("example.pay:account:1");
const OTHER_TD: &str = "urn:example:non-sca:receipt:1";
const OTHER_ACCOUNT_TD: &str = "urn:example:non-sca:account:1";

// Spec coverage map:
// - OID4VP 6.1: duplicate ids are ignored after first; unknown formats do not kill satisfiable options.
// - OID4VP 6.2: omitted credential_sets means all credentials are required.
// - OID4VP 6.3/6.4.1: claims, claim_sets, claim paths, value filters.
// - OID4VP transaction_data: malformed entries are ignored; usable ids target DCQL queries.
// - TS12 3.3: each candidate credential selects the first compatible targeted entry.
// - TS12 3.3: incompatible payloads are skipped, then the next entry is tried.
// - TS12 3.4: SCA-targeted credential set alternatives must be transposable.
// - TS12 3.4: non-SCA transaction_data entries are not subject to SCA-only constraints.
// - TS12 3.4: alternatives resolving to different transaction_data keep that binding per option.
// - TS12 3.4: per-slot display order/default follows the alternatives' first appearances.

#[derive(Debug, Clone, Deserialize)]
struct CredentialPackage {
    #[serde(default)]
    credentials: Vec<JsonCredential>,
}

#[derive(Debug, Clone, Deserialize)]
struct JsonCredential {
    id: String,
    format: CredentialFormat,

    #[serde(default)]
    holder_binding: bool,
    vct: Option<String>,
    extends_vcts: Option<Vec<String>>,
    doctype: Option<String>,

    #[serde(default)]
    trusted_authorities: Vec<TrustedAuthority>,

    #[serde(default)]
    transaction_data_types: Vec<TransactionDataType>,

    #[serde(default)]
    accepted_transaction_payload_kinds: Vec<String>,

    #[serde(default = "default_claims_value")]
    claims: Value,
}

fn default_claims_value() -> Value {
    Value::Object(Map::new())
}

#[derive(Debug, Clone, Deserialize)]
struct RequestFixture {
    #[serde(flatten)]
    dcql_query: dcapi_dcql::DcqlQuery,
    transaction_data: Option<Vec<TransactionData>>,
}

#[derive(Debug, Clone)]
struct JsonStore {
    creds: FxHashMap<String, JsonCredential>,
}

impl JsonStore {
    fn from_package(pkg: CredentialPackage) -> Self {
        let creds = pkg
            .credentials
            .into_iter()
            .map(|c| (c.id.clone(), c))
            .collect();
        Self { creds }
    }

    fn get(&self, id: &str) -> &JsonCredential {
        self.creds
            .get(id)
            .unwrap_or_else(|| panic!("missing credential id in store: {id}"))
    }
}

impl CredentialStore for JsonStore {
    type CredentialRef = String;
    type ReadError = std::io::Error;

    fn from_reader(reader: &mut dyn std::io::Read) -> Result<Self, Self::ReadError> {
        let package: CredentialPackage = serde_json::from_reader(reader)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
        Ok(Self::from_package(package))
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.creds
            .values()
            .filter(|c| format.map(|f| c.format == f).unwrap_or(true))
            .map(|c| c.id.clone())
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        self.get(cred).format
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        let c = self.get(cred);
        let Some(current_vct) = c.vct.as_deref() else {
            return false;
        };
        current_vct == vct
            || c.extends_vcts
                .as_ref()
                .is_some_and(|chain| chain.iter().any(|entry| entry == vct))
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(cred).holder_binding
    }

    fn has_doctype(&self, cred: &Self::CredentialRef, doctype: &str) -> bool {
        self.get(cred).doctype.as_deref() == Some(doctype)
    }

    fn can_sign_transaction_data(
        &self,
        cred: &Self::CredentialRef,
        transaction_data: &TransactionData,
    ) -> bool {
        let c = self.get(cred);
        let type_matches = c
            .transaction_data_types
            .iter()
            .any(|t| t.r#type == transaction_data.r#type);
        if !type_matches {
            return false;
        }

        if c.accepted_transaction_payload_kinds.is_empty() {
            return true;
        }

        transaction_data
            .extra
            .get("payload")
            .and_then(|payload| payload.get("kind"))
            .and_then(Value::as_str)
            .is_some_and(|kind| {
                c.accepted_transaction_payload_kinds
                    .iter()
                    .any(|accepted| accepted == kind)
            })
    }

    fn has_claim_path(
        &self,
        cred: &Self::CredentialRef,
        path: &dcapi_dcql::ClaimsPathPointer,
    ) -> bool {
        dcapi_dcql::select_nodes(&self.get(cred).claims, path).is_ok()
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &dcapi_dcql::ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let Ok(nodes) = dcapi_dcql::select_nodes(&self.get(cred).claims, path) else {
            return ValueMatch::NoMatch;
        };

        if nodes.iter().any(|node| {
            expected_values
                .iter()
                .any(|value| claim_value_matches_json(value, node))
        }) {
            ValueMatch::Match
        } else {
            ValueMatch::NoMatch
        }
    }

    fn matches_trusted_authorities(
        &self,
        cred: &Self::CredentialRef,
        trusted_authorities: &[TrustedAuthority],
    ) -> bool {
        let c = self.get(cred);
        trusted_authorities.iter().all(|ta| {
            c.trusted_authorities.iter().any(|cred_ta| {
                cred_ta.r#type == ta.r#type && cred_ta.values.iter().any(|v| ta.values.contains(v))
            })
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AltSummary {
    dcql_id: String,
    credential_id: Option<String>,
    selected_claim_ids: Vec<String>,
    transaction_data_ids: Vec<usize>,
}

type SlotSummary = Vec<AltSummary>;
type SetSummary = Vec<SlotSummary>;
type PlanSummary = Vec<SetSummary>;

fn parse_request(value: Value) -> RequestFixture {
    serde_json::from_value(value).expect("request fixture must deserialize")
}

fn request_parse_error(value: Value) -> String {
    serde_json::from_value::<RequestFixture>(value)
        .expect_err("request fixture must fail to deserialize")
        .to_string()
}

fn store(value: Value) -> JsonStore {
    JsonStore::from_package(serde_json::from_value(value).expect("credential package must parse"))
}

fn plan_ok(request: Value, credentials: Value) -> DcqlOutput<String> {
    plan_ok_with_options(request, credentials, PlanOptions::default())
}

fn plan_ok_with_options(
    request: Value,
    credentials: Value,
    options: PlanOptions,
) -> DcqlOutput<String> {
    let request = parse_request(request);
    let store = store(credentials);
    plan_selection(
        &request.dcql_query,
        request.transaction_data.as_deref(),
        &store,
        &options,
    )
    .expect("expected satisfiable plan")
}

fn plan_err(request: Value, credentials: Value) -> PlanError {
    let request = parse_request(request);
    let store = store(credentials);
    plan_selection(
        &request.dcql_query,
        request.transaction_data.as_deref(),
        &store,
        &PlanOptions::default(),
    )
    .expect_err("expected planner error")
}

fn assert_invalid_query(err: PlanError, expected: &str) {
    match err {
        PlanError::InvalidQuery(message) => assert!(
            message.contains(expected),
            "expected invalid query containing {expected:?}, got {message:?}"
        ),
        other => panic!("expected InvalidQuery, got {other:?}"),
    }
}

fn assert_unsatisfied(err: PlanError) {
    assert!(
        matches!(err, PlanError::Unsatisfied),
        "expected Unsatisfied, got {err:?}"
    );
}

fn assert_plan(plan: &DcqlOutput<String>, expected: PlanSummary) {
    assert_eq!(summarize_plan(plan), canonicalize_expected(expected));
}

fn summarize_plan(plan: &DcqlOutput<String>) -> PlanSummary {
    let mut sets = plan
        .presentation_sets
        .iter()
        .map(|set| {
            let mut slots = set
                .iter()
                .map(|slot| {
                    let mut alternatives = slot
                        .alternatives
                        .iter()
                        .map(|selection| {
                            let mut selected_claim_ids = selection
                                .selected_claims
                                .iter()
                                .filter_map(|claim| claim.id.clone())
                                .collect::<Vec<_>>();
                            selected_claim_ids.sort();

                            let mut transaction_data_ids = selection.transaction_data_ids.clone();
                            transaction_data_ids.sort_unstable();

                            AltSummary {
                                dcql_id: selection.dcql_id.clone(),
                                credential_id: selection.credential_id.clone(),
                                selected_claim_ids,
                                transaction_data_ids: transaction_data_ids.clone(),
                            }
                        })
                        .collect::<Vec<_>>();
                    alternatives.sort();
                    alternatives
                })
                .collect::<Vec<_>>();
            slots.sort();
            slots
        })
        .collect::<Vec<_>>();
    sets.sort();
    sets
}

fn canonicalize_expected(mut expected: PlanSummary) -> PlanSummary {
    for set in &mut expected {
        for slot in set.iter_mut() {
            for alt in slot.iter_mut() {
                alt.selected_claim_ids.sort();
                alt.transaction_data_ids.sort_unstable();
            }
            slot.sort();
        }
        set.sort();
    }
    expected.sort();
    expected
}

fn alt(dcql_id: &str, credential_id: &str) -> AltSummary {
    alt_claims_tx(dcql_id, Some(credential_id), &[], &[])
}

fn alt_tx(dcql_id: &str, credential_id: &str, transaction_data_ids: &[usize]) -> AltSummary {
    alt_claims_tx(dcql_id, Some(credential_id), &[], transaction_data_ids)
}

fn alt_claims(dcql_id: &str, credential_id: &str, selected_claim_ids: &[&str]) -> AltSummary {
    alt_claims_tx(dcql_id, Some(credential_id), selected_claim_ids, &[])
}

fn alt_claims_tx(
    dcql_id: &str,
    credential_id: Option<&str>,
    selected_claim_ids: &[&str],
    transaction_data_ids: &[usize],
) -> AltSummary {
    AltSummary {
        dcql_id: dcql_id.to_string(),
        credential_id: credential_id.map(ToString::to_string),
        selected_claim_ids: selected_claim_ids
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        transaction_data_ids: transaction_data_ids.to_vec(),
    }
}

fn none(dcql_id: &str) -> AltSummary {
    alt_claims_tx(dcql_id, None, &[], &[])
}

fn sd_query(id: &str, vct: &str) -> Value {
    json!({ "id": id, "format": "dc+sd-jwt", "meta": { "vct_values": [vct] } })
}

fn sd_query_without_holder_binding(id: &str, vct: &str) -> Value {
    json!({
        "id": id,
        "format": "dc+sd-jwt",
        "meta": { "vct_values": [vct] },
        "require_cryptographic_holder_binding": false
    })
}

fn mdoc_query(id: &str, doctype: &str) -> Value {
    json!({ "id": id, "format": "mso_mdoc", "meta": { "doctype_value": doctype } })
}

fn sd_credential(id: &str, vct: &str) -> Value {
    json!({
        "id": id,
        "format": "dc+sd-jwt",
        "holder_binding": true,
        "vct": vct,
        "claims": {}
    })
}

fn sd_credential_without_holder_binding(id: &str, vct: &str) -> Value {
    json!({
        "id": id,
        "format": "dc+sd-jwt",
        "holder_binding": false,
        "vct": vct,
        "claims": {}
    })
}

fn mdoc_credential(id: &str, doctype: &str) -> Value {
    json!({
        "id": id,
        "format": "mso_mdoc",
        "doctype": doctype,
        "claims": {}
    })
}

fn with_transaction_types(mut credential: Value, types: &[&str]) -> Value {
    credential["transaction_data_types"] = Value::Array(
        types
            .iter()
            .map(|r#type| json!({ "type": *r#type }))
            .collect(),
    );
    credential
}

fn with_accepted_payload_kinds(mut credential: Value, kinds: &[&str]) -> Value {
    credential["accepted_transaction_payload_kinds"] =
        Value::Array(kinds.iter().map(|kind| json!(*kind)).collect());
    credential
}

fn with_claims(mut credential: Value, claims: Value) -> Value {
    credential["claims"] = claims;
    credential
}

fn package(credentials: Vec<Value>) -> Value {
    json!({ "credentials": credentials })
}

fn claim_value_matches_json(expected: &ClaimValue, actual: &Value) -> bool {
    match expected {
        ClaimValue::String(value) => actual.as_str() == Some(value),
        ClaimValue::Integer(value) => actual.as_i64() == Some(*value),
        ClaimValue::Boolean(value) => actual.as_bool() == Some(*value),
    }
}

mod oid4vp_query_structure {
    use super::*;

    #[test]
    fn default_options_target_ts12_sca_prefix_only() {
        let options = PlanOptions::default();

        assert_eq!(options.ts12_prefixes, vec![DEFAULT_TS12_PREFIX.to_string()]);
        assert!(options.is_ts12_transaction_data_type(SCA_PAY_V1));
        assert!(options.is_ts12_transaction_data_type(SCA_PAY_V2));
        assert!(options.is_ts12_transaction_data_type(SCA_CARD));
        assert!(options.is_ts12_transaction_data_type(SCA_ACCOUNT));
        assert!(!options.is_ts12_transaction_data_type(OTHER_TD));
        assert!(!options.is_ts12_transaction_data_type(OTHER_ACCOUNT_TD));
    }

    #[test]
    fn targeted_transaction_data_prefixes_are_configurable() {
        let options = PlanOptions {
            ts12_prefixes: vec!["urn:bank-a:sca:".to_string(), "urn:bank-b:sca:".to_string()],
            ..PlanOptions::default()
        };

        assert!(options.is_ts12_transaction_data_type("urn:bank-a:sca:payment:1"));
        assert!(options.is_ts12_transaction_data_type("urn:bank-b:sca:card:1"));
        assert!(!options.is_ts12_transaction_data_type(SCA_CARD));
        assert!(!options.is_ts12_transaction_data_type("urn:bank-c:sca:payment:1"));
    }

    #[test]
    fn empty_targeted_transaction_data_prefixes_disable_targeted_matching() {
        let options = PlanOptions {
            ts12_prefixes: Vec::new(),
            ..PlanOptions::default()
        };

        assert!(!options.is_ts12_transaction_data_type(SCA_PAY_V1));
    }

    #[test]
    fn credentials_array_must_not_be_empty() {
        let err = request_parse_error(json!({ "credentials": [] }));
        assert!(err.contains("credentials must contain at least one credential query"));
    }

    #[test]
    fn duplicate_credential_query_ids_are_ignored_after_first() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("pid", "vct:pid"),
                    mdoc_query("pid", "org.iso.18013.5.1.mDL")
                ]
            }),
            package(vec![
                sd_credential("sd-pid", "vct:pid"),
                mdoc_credential("mdl", "org.iso.18013.5.1.mDL"),
            ]),
        );

        assert_plan(&plan, vec![vec![vec![alt("pid", "sd-pid")]]]);
    }

    #[test]
    fn claim_sets_without_claims_are_ignored() {
        let plan = plan_ok(
            json!({
                "credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": { "vct_values": ["vct:pid"] },
                    "claim_sets": [["given_name"]]
                }]
            }),
            package(vec![sd_credential("sd-pid", "vct:pid")]),
        );

        assert_plan(&plan, vec![vec![vec![alt("pid", "sd-pid")]]]);
    }

    #[test]
    fn unknown_format_option_is_pruned_without_rejecting_supported_option() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    { "id": "future", "format": "dc+future", "meta": {} },
                    sd_query("pid", "vct:pid")
                ],
                "credential_sets": [{ "options": [["future"], ["pid"]] }]
            }),
            package(vec![sd_credential("sd-pid", "vct:pid")]),
        );

        assert_plan(&plan, vec![vec![vec![alt("pid", "sd-pid")]]]);
    }
}

mod credential_matching {
    use super::*;

    #[test]
    fn sd_jwt_requires_holder_binding_by_default() {
        let err = plan_err(
            json!({ "credentials": [sd_query("pid", "vct:pid")] }),
            package(vec![sd_credential_without_holder_binding(
                "sd-pid", "vct:pid",
            )]),
        );

        assert_unsatisfied(err);
    }

    #[test]
    fn sd_jwt_holder_binding_requirement_can_be_disabled_without_transaction_data() {
        let plan = plan_ok(
            json!({ "credentials": [sd_query_without_holder_binding("pid", "vct:pid")] }),
            package(vec![sd_credential_without_holder_binding(
                "sd-pid", "vct:pid",
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt("pid", "sd-pid")]]]);
    }

    #[test]
    fn sd_jwt_vct_values_match_direct_or_extends_chain() {
        let mut direct = sd_credential("direct", "vct:pid");
        let mut child = sd_credential("child", "vct:pid-child");
        child["extends_vcts"] = json!(["vct:pid"]);
        direct["claims"] = json!({ "given_name": "Alice" });
        child["claims"] = json!({ "given_name": "Alice" });

        let plan = plan_ok(
            json!({ "credentials": [sd_query("pid", "vct:pid")] }),
            package(vec![direct, child, sd_credential("other", "vct:other")]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![alt("pid", "child"), alt("pid", "direct")]]],
        );
    }

    #[test]
    fn claims_without_claim_sets_select_all_claims_that_match() {
        let mut query = sd_query("pid", "vct:pid");
        query["claims"] = json!([
            { "id": "given_name", "path": ["given_name"] },
            { "id": "age_over_18", "path": ["age_over_18"], "values": [true] }
        ]);

        let plan = plan_ok(
            json!({ "credentials": [query] }),
            package(vec![with_claims(
                sd_credential("sd-pid", "vct:pid"),
                json!({ "given_name": "Alice", "age_over_18": true }),
            )]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![alt_claims(
                "pid",
                "sd-pid",
                &["given_name", "age_over_18"],
            )]]],
        );
    }

    #[test]
    fn claim_sets_select_first_satisfiable_claim_set() {
        let mut query = sd_query("pid", "vct:pid");
        query["claims"] = json!([
            { "id": "family_name", "path": ["family_name"] },
            { "id": "given_name", "path": ["given_name"] }
        ]);
        query["claim_sets"] = json!([["family_name"], ["given_name"]]);

        let plan = plan_ok(
            json!({ "credentials": [query] }),
            package(vec![with_claims(
                sd_credential("sd-pid", "vct:pid"),
                json!({ "given_name": "Alice" }),
            )]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![alt_claims("pid", "sd-pid", &["given_name"])]]],
        );
    }

    #[test]
    fn malformed_claim_sets_are_ignored() {
        let mut query = sd_query("pid", "vct:pid");
        query["claims"] = json!([{ "id": "given_name", "path": ["given_name"] }]);
        query["claim_sets"] = json!([["missing"]]);

        let plan = plan_ok(
            json!({ "credentials": [query] }),
            package(vec![with_claims(
                sd_credential("sd-pid", "vct:pid"),
                json!({ "given_name": "Alice" }),
            )]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![alt_claims("pid", "sd-pid", &["given_name"])]]],
        );
    }

    #[test]
    fn mdoc_null_path_component_matches_array_elements() {
        let mut query = mdoc_query("mdl", "org.iso.18013.5.1.mDL");
        query["claims"] = json!([{
            "id": "b",
            "path": ["org.iso.18013.5.1", "driving_privileges", null, "vehicle_category_code"],
            "values": ["B"]
        }]);

        let plan = plan_ok(
            json!({ "credentials": [query] }),
            package(vec![with_claims(
                mdoc_credential("mdl-1", "org.iso.18013.5.1.mDL"),
                json!({
                    "org.iso.18013.5.1": {
                        "driving_privileges": [
                            { "vehicle_category_code": "A" },
                            { "vehicle_category_code": "B" }
                        ]
                    }
                }),
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_claims("mdl", "mdl-1", &["b"])]]]);
    }

    #[test]
    fn trusted_authorities_require_type_and_value_overlap() {
        let mut query = sd_query("pid", "vct:pid");
        query["trusted_authorities"] = json!([{ "type": "aki", "values": ["root-a"] }]);

        let mut trusted = sd_credential("trusted", "vct:pid");
        trusted["trusted_authorities"] = json!([{ "type": "aki", "values": ["root-a"] }]);

        let mut wrong_type = sd_credential("wrong-type", "vct:pid");
        wrong_type["trusted_authorities"] = json!([{ "type": "x5c", "values": ["root-a"] }]);

        let mut wrong_value = sd_credential("wrong-value", "vct:pid");
        wrong_value["trusted_authorities"] = json!([{ "type": "aki", "values": ["root-b"] }]);

        let plan = plan_ok(
            json!({ "credentials": [query] }),
            package(vec![trusted, wrong_type, wrong_value]),
        );

        assert_plan(&plan, vec![vec![vec![alt("pid", "trusted")]]]);
    }
}

mod credential_sets {
    use super::*;

    #[test]
    fn omitted_credential_sets_request_all_supported_credentials_as_required_slots() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("pid", "vct:pid"),
                    mdoc_query("mdl", "org.iso.18013.5.1.mDL")
                ]
            }),
            package(vec![
                sd_credential("sd-pid", "vct:pid"),
                mdoc_credential("mdl-1", "org.iso.18013.5.1.mDL"),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![alt("pid", "sd-pid")], vec![alt("mdl", "mdl-1")]]],
        );
    }

    #[test]
    fn simple_required_set_options_merge_into_one_choice_slot() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("pid_sd", "vct:pid"),
                    mdoc_query("pid_mdoc", "org.iso.18013.5.1.mDL")
                ],
                "credential_sets": [{ "options": [["pid_sd"], ["pid_mdoc"]] }]
            }),
            package(vec![
                sd_credential("sd-pid", "vct:pid"),
                mdoc_credential("mdl-pid", "org.iso.18013.5.1.mDL"),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![
                alt("pid_sd", "sd-pid"),
                alt("pid_mdoc", "mdl-pid"),
            ]]],
        );
    }

    #[test]
    fn optional_set_prefer_absent_exposes_empty_choice_first() {
        let plan = plan_ok_with_options(
            json!({
                "credentials": [
                    sd_query("sca", "vct:sca"),
                    sd_query("pid", "vct:pid")
                ],
                "credential_sets": [
                    { "options": [["sca"]] },
                    { "required": false, "options": [["pid"]] }
                ]
            }),
            package(vec![
                sd_credential("sca-1", "vct:sca"),
                sd_credential("pid-1", "vct:pid"),
            ]),
            PlanOptions {
                optional_credential_sets_mode: OptionalCredentialSetsMode::PreferAbsent,
                ..PlanOptions::default()
            },
        );

        assert_plan(
            &plan,
            vec![vec![
                vec![alt("sca", "sca-1")],
                vec![alt("pid", "pid-1"), none("pid")],
            ]],
        );
    }

    #[test]
    fn transposable_options_decompose_into_independent_slots() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("pid_1", "vct:pid-1"),
                    sd_query("pid_2", "vct:pid-2")
                ],
                "credential_sets": [{
                    "options": [
                        ["sca_card", "pid_1"],
                        ["sca_card", "pid_2"],
                        ["sca_card"]
                    ]
                }]
            }),
            package(vec![
                sd_credential("card", "vct:sca-card"),
                sd_credential("pid-1", "vct:pid-1"),
                sd_credential("pid-2", "vct:pid-2"),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![
                vec![alt("sca_card", "card")],
                vec![alt("pid_1", "pid-1"), alt("pid_2", "pid-2"), none("pid_1")],
            ]],
        );
    }
}

mod transaction_data {
    use super::*;

    #[test]
    fn transaction_data_with_empty_credential_ids_is_ignored() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [{ "type": SCA_PAY_V1, "credential_ids": [] }]
            }),
            package(vec![with_transaction_types(
                sd_credential("sca-1", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt("sca", "sca-1")]]]);
    }

    #[test]
    fn transaction_data_with_unknown_credential_ids_is_ignored() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [{ "type": SCA_PAY_V1, "credential_ids": ["missing"] }]
            }),
            package(vec![with_transaction_types(
                sd_credential("sca-1", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt("sca", "sca-1")]]]);
    }

    #[test]
    fn single_transaction_data_binds_to_the_targeted_slot() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [{ "type": SCA_PAY_V1, "credential_ids": ["sca"] }]
            }),
            package(vec![with_transaction_types(
                sd_credential("sca-1", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca", "sca-1", &[0])]]]);
    }

    #[test]
    fn credentials_without_matching_transaction_type_are_excluded() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [{ "type": SCA_PAY_V1, "credential_ids": ["sca"] }]
            }),
            package(vec![
                with_transaction_types(sd_credential("can-sign", "vct:sca"), &[SCA_PAY_V1]),
                with_transaction_types(sd_credential("cannot-sign", "vct:sca"), &[OTHER_TD]),
            ]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca", "can-sign", &[0])]]]);
    }

    #[test]
    fn first_compatible_transaction_data_wins_per_credential() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [
                    { "type": SCA_PAY_V2, "credential_ids": ["sca"] },
                    { "type": SCA_PAY_V1, "credential_ids": ["sca"] }
                ]
            }),
            package(vec![
                with_transaction_types(
                    sd_credential("new-card", "vct:sca"),
                    &[SCA_PAY_V2, SCA_PAY_V1],
                ),
                with_transaction_types(sd_credential("old-card", "vct:sca"), &[SCA_PAY_V1]),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![vec![
                alt_tx("sca", "new-card", &[0]),
                alt_tx("sca", "old-card", &[1]),
            ]]],
        );
    }

    #[test]
    fn unsupported_newer_entry_falls_back_to_older_compatible_entry() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [
                    { "type": SCA_PAY_V2, "credential_ids": ["sca"] },
                    { "type": SCA_PAY_V1, "credential_ids": ["sca"] }
                ]
            }),
            package(vec![with_transaction_types(
                sd_credential("old-card", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca", "old-card", &[1])]]]);
    }

    #[test]
    fn payload_incompatible_entries_are_skipped_before_fallback() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [
                    {
                        "type": SCA_PAY_V2,
                        "credential_ids": ["sca"],
                        "payload": { "kind": "new" }
                    },
                    {
                        "type": SCA_PAY_V1,
                        "credential_ids": ["sca"],
                        "payload": { "kind": "legacy" }
                    }
                ]
            }),
            package(vec![with_accepted_payload_kinds(
                with_transaction_types(
                    sd_credential("legacy-card", "vct:sca"),
                    &[SCA_PAY_V2, SCA_PAY_V1],
                ),
                &["legacy"],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca", "legacy-card", &[1])]]]);
    }

    #[test]
    fn credentials_without_compatible_transaction_payload_are_excluded() {
        let err = plan_err(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [{
                    "type": SCA_PAY_V1,
                    "credential_ids": ["sca"],
                    "payload": { "kind": "new" }
                }]
            }),
            package(vec![with_accepted_payload_kinds(
                with_transaction_types(sd_credential("legacy-card", "vct:sca"), &[SCA_PAY_V1]),
                &["legacy"],
            )]),
        );

        assert_unsatisfied(err);
    }

    #[test]
    fn selected_credential_gets_exactly_one_transaction_data_entry() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca", "vct:sca")],
                "transaction_data": [
                    { "type": SCA_PAY_V1, "credential_ids": ["sca"] },
                    { "type": SCA_PAY_V1, "credential_ids": ["sca"] }
                ]
            }),
            package(vec![with_transaction_types(
                sd_credential("sca-1", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca", "sca-1", &[0])]]]);
    }

    #[test]
    fn transaction_data_targeting_non_holder_bound_query_is_ignored() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query_without_holder_binding("sca", "vct:sca")],
                "transaction_data": [{ "type": SCA_PAY_V1, "credential_ids": ["sca"] }]
            }),
            package(vec![with_transaction_types(
                sd_credential_without_holder_binding("sca-1", "vct:sca"),
                &[SCA_PAY_V1],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt("sca", "sca-1")]]]);
    }
}

mod ts12_advanced_profile {
    use super::*;

    #[test]
    fn all_sca_transaction_ids_must_appear_in_options_of_the_same_credential_set() {
        let err = plan_err(
            json!({
                "credentials": [
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("sca_account", "vct:sca-account")
                ],
                "credential_sets": [
                    { "options": [["sca_card"]] },
                    { "options": [["sca_account"]] }
                ],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] },
                    { "type": SCA_ACCOUNT, "credential_ids": ["sca_account"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("card", "vct:sca-card"), &[SCA_CARD]),
                with_transaction_types(sd_credential("account", "vct:sca-account"), &[SCA_ACCOUNT]),
            ]),
        );

        assert_invalid_query(err, "same credential set");
    }

    #[test]
    fn non_sca_transaction_data_can_target_different_credential_sets() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("receipt", "vct:receipt"),
                    sd_query("account", "vct:account")
                ],
                "credential_sets": [
                    { "options": [["receipt"]] },
                    { "options": [["account"]] }
                ],
                "transaction_data": [
                    { "type": OTHER_TD, "credential_ids": ["receipt"] },
                    { "type": OTHER_ACCOUNT_TD, "credential_ids": ["account"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("receipt-1", "vct:receipt"), &[OTHER_TD]),
                with_transaction_types(
                    sd_credential("account-1", "vct:account"),
                    &[OTHER_ACCOUNT_TD],
                ),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![
                vec![alt_tx("receipt", "receipt-1", &[0])],
                vec![alt_tx("account", "account-1", &[1])],
            ]],
        );
    }

    #[test]
    fn non_sca_transaction_data_does_not_trigger_ts12_transposability_rejection() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("receipt", "vct:receipt"),
                    sd_query("pid_1", "vct:pid-1"),
                    sd_query("pid_2", "vct:pid-2"),
                    sd_query("loyalty", "vct:loyalty")
                ],
                "credential_sets": [{
                    "options": [
                        ["receipt", "pid_1"],
                        ["receipt", "pid_2", "loyalty"],
                        ["receipt"]
                    ]
                }],
                "transaction_data": [
                    { "type": OTHER_TD, "credential_ids": ["receipt"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("receipt-1", "vct:receipt"), &[OTHER_TD]),
                sd_credential("pid-1", "vct:pid-1"),
                sd_credential("pid-2", "vct:pid-2"),
                sd_credential("loyalty-1", "vct:loyalty"),
            ]),
        );

        assert!(!plan.presentation_sets.is_empty());
    }

    #[test]
    fn alternative_with_multiple_sca_entries_for_same_credential_uses_first_match() {
        let plan = plan_ok(
            json!({
                "credentials": [sd_query("sca_card", "vct:sca-card")],
                "credential_sets": [{ "options": [["sca_card"]] }],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] },
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] }
                ]
            }),
            package(vec![with_transaction_types(
                sd_credential("card", "vct:sca-card"),
                &[SCA_CARD],
            )]),
        );

        assert_plan(&plan, vec![vec![vec![alt_tx("sca_card", "card", &[0])]]]);
    }

    #[test]
    fn transposable_sca_options_decompose_into_slots_with_optional_none() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("pid_1", "vct:pid-1"),
                    sd_query("pid_2", "vct:pid-2")
                ],
                "credential_sets": [{
                    "options": [
                        ["sca_card", "pid_1"],
                        ["sca_card", "pid_2"],
                        ["sca_card"]
                    ]
                }],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("card", "vct:sca-card"), &[SCA_CARD]),
                sd_credential("pid-1", "vct:pid-1"),
                sd_credential("pid-2", "vct:pid-2"),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![
                vec![alt_tx("sca_card", "card", &[0])],
                vec![alt("pid_1", "pid-1"), alt("pid_2", "pid-2"), none("pid_1")],
            ]],
        );
    }

    #[test]
    fn non_transposable_sca_options_are_invalid() {
        let err = plan_err(
            json!({
                "credentials": [
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("pid_1", "vct:pid-1"),
                    sd_query("pid_2", "vct:pid-2"),
                    sd_query("loyalty", "vct:loyalty")
                ],
                "credential_sets": [{
                    "options": [
                        ["sca_card", "pid_1"],
                        ["sca_card", "pid_2", "loyalty"],
                        ["sca_card"]
                    ]
                }],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("card", "vct:sca-card"), &[SCA_CARD]),
                sd_credential("pid-1", "vct:pid-1"),
                sd_credential("pid-2", "vct:pid-2"),
                sd_credential("loyalty-1", "vct:loyalty"),
            ]),
        );

        assert_invalid_query(err, "not transposable");
    }

    #[test]
    fn different_sca_options_keep_their_own_transaction_data_binding() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("sca_account", "vct:sca-account"),
                    sd_query("pid", "vct:pid")
                ],
                "credential_sets": [{
                    "options": [
                        ["sca_card", "pid"],
                        ["sca_account", "pid"]
                    ]
                }],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] },
                    { "type": SCA_ACCOUNT, "credential_ids": ["sca_account"] }
                ]
            }),
            package(vec![
                with_transaction_types(sd_credential("card", "vct:sca-card"), &[SCA_CARD]),
                with_transaction_types(sd_credential("account", "vct:sca-account"), &[SCA_ACCOUNT]),
                sd_credential("pid-1", "vct:pid"),
            ]),
        );

        assert_plan(
            &plan,
            vec![vec![
                vec![
                    alt_tx("sca_card", "card", &[0]),
                    alt_tx("sca_account", "account", &[1]),
                ],
                vec![alt("pid", "pid-1")],
            ]],
        );
    }

    #[test]
    fn slot_display_order_and_default_follow_first_alternative() {
        let plan = plan_ok(
            json!({
                "credentials": [
                    sd_query("pid_2", "vct:pid-2"),
                    sd_query("sca_card", "vct:sca-card"),
                    sd_query("pid_1", "vct:pid-1")
                ],
                "credential_sets": [{
                    "options": [
                        ["sca_card", "pid_1"],
                        ["sca_card", "pid_2"],
                        ["sca_card"]
                    ]
                }],
                "transaction_data": [
                    { "type": SCA_CARD, "credential_ids": ["sca_card"] }
                ]
            }),
            package(vec![
                sd_credential("pid-2", "vct:pid-2"),
                with_transaction_types(sd_credential("card", "vct:sca-card"), &[SCA_CARD]),
                sd_credential("pid-1", "vct:pid-1"),
            ]),
        );

        let pid_slot = plan
            .presentation_sets
            .first()
            .expect("one presentation set")
            .iter()
            .find(|slot| {
                slot.alternatives
                    .iter()
                    .any(|selection| selection.dcql_id == "pid_1" || selection.dcql_id == "pid_2")
            })
            .expect("pid slot");

        let ordered = pid_slot
            .alternatives
            .iter()
            .map(|selection| {
                (
                    selection.dcql_id.as_str(),
                    selection.credential_id.as_deref(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            ordered,
            vec![
                ("pid_1", Some("pid-1")),
                ("pid_2", Some("pid-2")),
                ("pid_1", None)
            ]
        );
    }
}
