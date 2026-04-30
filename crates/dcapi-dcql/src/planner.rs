use crate::models::{
    ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, Meta, TransactionData,
    TrustedAuthority,
};
use crate::path::{ClaimsPathPointer, PathElement};
use crate::store::{CredentialFormat, CredentialStore, ValueMatch};
use rustc_hash::FxHashSet;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Resolved matching context for one Credential Query id.
#[derive(Debug, Clone)]
pub struct QueryMatches<C> {
    /// Credential Query id.
    pub id: String,
    /// Requested credential format.
    pub format: CredentialFormat,
    /// Parsed typed `meta` object.
    pub meta: Meta,
    /// Whether multiple presentations are allowed in the response.
    pub multiple: bool,
    /// Whether cryptographic holder binding is required.
    pub require_holder_binding: bool,
    /// Trusted authority constraints copied from query.
    pub trusted_authorities: Option<Vec<TrustedAuthority>>,
    /// Claims selected after evaluating `claims` / `claim_sets`.
    pub selected_claims: Vec<ClaimsQuery>,
    /// Candidate credential references that satisfy this query.
    pub credentials: Vec<C>,
}

/// How to choose options inside each Credential Set Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialSetOptionMode {
    /// Keep all satisfiable options.
    AllSatisfiable,
    /// Keep only the first satisfiable option in declared order.
    FirstSatisfiableOnly,
}

/// How optional Credential Set Queries are incorporated into alternatives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionalCredentialSetsMode {
    /// Prefer including satisfiable optional sets first, then alternatives without them.
    PreferPresent,
    /// Prefer omitting optional sets first, then alternatives that include them.
    PreferAbsent,
    /// If an optional set is satisfiable, always include one option for it.
    AlwaysPresentIfSatisfiable,
}

/// Default TS12 SCA transaction-data type prefix.
pub const DEFAULT_TS12_PREFIX: &str = "urn:eudi:sca:";

/// Planner configuration knobs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlanOptions {
    /// Option-selection policy for each Credential Set Query.
    pub credential_set_option_mode: CredentialSetOptionMode,
    /// Inclusion policy for optional Credential Set Queries.
    pub optional_credential_sets_mode: OptionalCredentialSetsMode,
    /// Transaction-data type prefixes that activate TS12 behavior.
    ///
    /// Configure this to support TS12-compatible deployments that use one or
    /// more SCA prefixes. An empty list disables TS12 handling.
    pub ts12_prefixes: Vec<String>,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            credential_set_option_mode: CredentialSetOptionMode::AllSatisfiable,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferPresent,
            ts12_prefixes: vec![DEFAULT_TS12_PREFIX.to_string()],
        }
    }
}

impl PlanOptions {
    /// Returns true if a transaction-data type is subject to TS12 rules.
    pub fn is_ts12_transaction_data_type(&self, r#type: &str) -> bool {
        self.ts12_prefixes
            .iter()
            .any(|prefix| !prefix.is_empty() && r#type.starts_with(prefix))
    }
}

#[derive(Debug, Clone)]
struct QueryIndex<'q> {
    queries: BTreeMap<String, &'q CredentialQuery>,
    transaction_data_targets: FxHashSet<String>,
}

impl<'q> QueryIndex<'q> {
    fn build(query: &'q DcqlQuery) -> Self {
        let mut queries = BTreeMap::new();
        let mut transaction_data_targets = FxHashSet::default();

        for credential_query in &query.credentials {
            let Some(id) = credential_query.id() else {
                continue;
            };
            let id = id.to_string();
            if queries.contains_key(&id) {
                continue;
            }
            if credential_query.format() != CredentialFormat::Unknown
                && credential_query_supports_transaction_data(credential_query)
            {
                transaction_data_targets.insert(id.clone());
            }
            queries.insert(id, credential_query);
        }

        Self {
            queries,
            transaction_data_targets,
        }
    }
}

fn credential_query_supports_transaction_data(query: &CredentialQuery) -> bool {
    query.format() != CredentialFormat::DcSdJwt
        || query.require_cryptographic_holder_binding() != Some(false)
}

#[derive(Debug, Clone)]
struct TransactionConstraints<'a> {
    data: &'a [TransactionData],
    generic_indices: Vec<usize>,
    ts12_indices: Vec<usize>,
}

impl<'a> TransactionConstraints<'a> {
    fn build(
        query: &DcqlQuery,
        index: &QueryIndex<'_>,
        transaction_data: Option<&'a [TransactionData]>,
        options: &PlanOptions,
    ) -> Result<Self, PlanError> {
        let data = transaction_data.unwrap_or_default();
        let usable_indices = data
            .iter()
            .enumerate()
            .filter_map(|(idx, item)| {
                item.credential_ids
                    .iter()
                    .any(|id| index.transaction_data_targets.contains(id))
                    .then_some(idx)
            })
            .collect::<Vec<_>>();
        let generic_indices = usable_indices
            .iter()
            .copied()
            .filter(|idx| !options.is_ts12_transaction_data_type(&data[*idx].r#type))
            .collect::<Vec<_>>();
        let ts12_indices = usable_indices
            .iter()
            .copied()
            .filter(|idx| options.is_ts12_transaction_data_type(&data[*idx].r#type))
            .collect::<Vec<_>>();

        Ts12CredentialSet::build(query, data, &ts12_indices, &index.transaction_data_targets)?;

        Ok(Self {
            data,
            generic_indices,
            ts12_indices,
        })
    }

    fn has_ts12(&self) -> bool {
        !self.ts12_indices.is_empty()
    }
}

#[derive(Debug, Clone)]
struct Ts12CredentialSet;

impl Ts12CredentialSet {
    fn build(
        query: &DcqlQuery,
        transaction_data: &[TransactionData],
        ts12_indices: &[usize],
        transaction_data_targets: &FxHashSet<String>,
    ) -> Result<Option<Self>, PlanError> {
        let ts12_ids = ts12_indices
            .iter()
            .filter_map(|idx| transaction_data.get(*idx))
            .flat_map(|data| data.credential_ids.iter().cloned())
            .filter(|id| transaction_data_targets.contains(id))
            .collect::<BTreeSet<_>>();
        if ts12_ids.is_empty() {
            return Ok(None);
        }

        let Some(credential_sets) = &query.credential_sets else {
            return Ok(Some(Self));
        };

        let containing_set = credential_sets.iter().enumerate().find_map(|(idx, set)| {
            let ids = set
                .options
                .iter()
                .flatten()
                .cloned()
                .collect::<BTreeSet<_>>();
            ts12_ids.is_subset(&ids).then_some(idx)
        });
        let Some(set_index) = containing_set else {
            return Err(PlanError::InvalidQuery(
                "SCA transaction_data credential ids must appear in the same credential set"
                    .to_string(),
            ));
        };

        let set = &credential_sets[set_index];
        let ts12_options = set
            .options
            .iter()
            .filter(|option| option.iter().any(|id| ts12_ids.contains(id.as_str())))
            .map(|option| option.iter().cloned().collect::<Config>())
            .collect::<Vec<_>>();
        let id_order = set
            .options
            .iter()
            .flatten()
            .filter(|id| ts12_options.iter().any(|option| option.contains(*id)))
            .cloned()
            .collect::<Vec<_>>();

        if decompose_slots(&ts12_options, &dedupe_order(id_order)).is_none() {
            return Err(PlanError::InvalidQuery(
                "SCA-targeted credential set options are not transposable".to_string(),
            ));
        }

        Ok(Some(Self))
    }
}

fn dedupe_order(values: Vec<String>) -> Vec<String> {
    let mut seen = FxHashSet::default();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

/// One entry in an inner selection set.
#[derive(Debug, Clone)]
struct SelectionEntry<C> {
    /// DCQL Credential Query id represented by this slot entry.
    dcql_id: String,
    /// Candidate selections for this id.
    selections: Vec<CredentialSelection<C>>,
}

/// One inner set: credentials presented together with bound transaction-data assignments.
#[derive(Debug, Clone)]
struct SelectionAlternative<C> {
    /// Independent per-id choices available to the UI.
    entries: Vec<SelectionEntry<C>>,
}

/// One selectable credential (or explicit empty choice) for a DCQL slot.
#[derive(Debug, Clone)]
pub struct CredentialSelection<C> {
    /// DCQL credential query id for this selection.
    pub dcql_id: String,
    /// Concrete credential reference, or `None` when representing "no credential".
    pub credential_id: Option<C>,
    /// Selected claim constraints for this dcql id.
    pub selected_claims: Vec<ClaimsQuery>,
    /// Transaction-data indices bound to this concrete selection.
    pub transaction_data_ids: Vec<usize>,
}

/// One independent credential choice slot inside a presentation set.
#[derive(Debug, Clone)]
pub struct SetAlternative<C> {
    /// Alternative credentials for this slot.
    pub alternatives: Vec<CredentialSelection<C>>,
}

/// A presentation set is a list of slots presented together.
pub type PresentationSet<C> = Vec<SetAlternative<C>>;

/// DCQL planner output, optimized for credential selection UI.
#[derive(Debug, Clone)]
pub struct DcqlOutput<C> {
    /// Presentation sets covering all valid DCQL combinations.
    pub presentation_sets: Vec<PresentationSet<C>>,
}

/// Query planning error.
#[derive(Debug, Clone, Error)]
pub enum PlanError {
    /// DCQL or transaction-data structure is invalid.
    #[error("invalid dcql query: {0}")]
    InvalidQuery(String),
    /// Query is valid but cannot be satisfied with available credentials.
    #[error(
        "unsatisfied dcql query: no credential combination satisfies all credential and transaction_data constraints"
    )]
    Unsatisfied,
}

/// Build a UI-oriented presentation plan from DCQL and optional transaction data.
///
/// The output is a list of presentation sets. Each set contains independent slots with
/// alternative credentials, and all transaction-data constraints are preserved.
pub fn plan_selection<S>(
    query: &DcqlQuery,
    transaction_data: Option<&[TransactionData]>,
    store: &S,
    options: &PlanOptions,
) -> Result<DcqlOutput<S::CredentialRef>, PlanError>
where
    S: CredentialStore,
    S::CredentialRef: Clone + Eq + std::hash::Hash,
{
    let query_index = QueryIndex::build(query);
    let mut matches_by_id = BTreeMap::new();
    for (query_id, credential_query) in &query_index.queries {
        let matches = match match_query(store, credential_query) {
            Ok(m) => m,
            Err(PlanError::InvalidQuery(_))
                if credential_query.format() == CredentialFormat::Unknown =>
            {
                // Skip credentials with unsupported formats so that
                // credential-set options referencing them are simply pruned.
                continue;
            }
            Err(e) => return Err(e),
        };
        matches_by_id.insert(query_id.to_owned(), matches);
    }

    let configs = build_configs(query, &matches_by_id, options)?;
    if configs.is_empty() {
        return Err(PlanError::Unsatisfied);
    }

    let transaction_constraints =
        TransactionConstraints::build(query, &query_index, transaction_data, options)?;

    let mut alternatives = Vec::new();
    for config in configs {
        let assignments = enumerate_transaction_assignments(
            store,
            &config,
            &matches_by_id,
            transaction_constraints.data,
            &transaction_constraints.generic_indices,
        );
        for assignment in assignments {
            let ordered_ids = order_config_ids(query, &config);
            let mut entries = Vec::new();
            for id in &ordered_ids {
                let Some(base_query) = matches_by_id.get(id) else {
                    continue;
                };
                let mut query_match = base_query.clone();
                let domain = assignment
                    .domains
                    .get(id)
                    .cloned()
                    .unwrap_or_else(|| query_match.credentials.clone());
                if domain.is_empty() {
                    continue;
                }
                let Some(query_definition) = query_index.queries.get(id) else {
                    continue;
                };
                let (selected_claims, filtered_domain) =
                    match_claim_selection(store, query_definition, domain);
                if filtered_domain.is_empty() {
                    continue;
                }

                let selection_ctx = SelectionBuildContext {
                    store,
                    options,
                    transaction_data: transaction_constraints.data,
                    ts12_indices: &transaction_constraints.ts12_indices,
                    assignment: &assignment,
                };
                let selections =
                    selections_for_query(&selection_ctx, id, selected_claims, filtered_domain);
                if selections.is_empty() {
                    continue;
                }

                query_match.credentials = selections
                    .iter()
                    .filter_map(|selection| selection.credential_id.clone())
                    .collect();

                entries.push(SelectionEntry {
                    dcql_id: id.clone(),
                    selections,
                });
            }

            if entries.len() != config.len()
                || entries.iter().any(|entry| entry.selections.is_empty())
            {
                continue;
            }

            alternatives.push(SelectionAlternative { entries });
        }
    }

    if alternatives.is_empty() {
        return Err(PlanError::Unsatisfied);
    }

    build_presentation_sets(query, alternatives, transaction_constraints.has_ts12())
}

#[derive(Debug, Clone)]
struct SlotEntry<C> {
    selections: Vec<CredentialSelection<C>>,
}

fn build_presentation_sets<C>(
    query: &DcqlQuery,
    alternatives: Vec<SelectionAlternative<C>>,
    has_ts12: bool,
) -> Result<DcqlOutput<C>, PlanError>
where
    C: Clone + Eq + std::hash::Hash,
{
    let alternative_maps = alternatives
        .into_iter()
        .map(|alternative| {
            alternative
                .entries
                .into_iter()
                .map(|entry| (entry.dcql_id.clone(), entry))
                .collect::<BTreeMap<_, _>>()
        })
        .collect::<Vec<_>>();

    let alternative_ids = alternative_maps
        .iter()
        .map(|alternative| alternative.keys().cloned().collect::<Config>())
        .collect::<Vec<_>>();
    let id_order = query_id_display_order(query, &alternative_ids);

    let Some(slots) = decompose_slots(&alternative_ids, &id_order) else {
        if has_ts12 {
            return Err(PlanError::InvalidQuery(
                "SCA-targeted credential set options are not transposable".to_string(),
            ));
        }
        return Ok(DcqlOutput {
            presentation_sets: build_unfactored_presentation_sets(alternative_maps),
        });
    };

    let mut presentation_set = Vec::new();
    for slot in slots {
        let mut entries = Vec::new();
        for id in &slot.ids {
            for alternative in &alternative_maps {
                if let Some(entry) = alternative.get(id) {
                    entries.push(SlotEntry {
                        selections: entry.selections.clone(),
                    });
                }
            }
        }

        let mut alternatives = build_slot_alternatives(&entries);
        if slot.optional {
            alternatives.push(CredentialSelection {
                dcql_id: slot.ids.first().cloned().unwrap_or_default(),
                credential_id: None,
                selected_claims: Vec::new(),
                transaction_data_ids: Vec::new(),
            });
        }
        if !alternatives.is_empty() {
            presentation_set.push(SetAlternative { alternatives });
        }
    }

    Ok(DcqlOutput {
        presentation_sets: vec![presentation_set],
    })
}

#[derive(Debug, Clone)]
struct SlotSpec {
    ids: Vec<String>,
    optional: bool,
}

fn query_id_display_order(query: &DcqlQuery, alternatives: &[Config]) -> Vec<String> {
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();

    if let Some(credential_sets) = &query.credential_sets {
        for set in credential_sets {
            for option in &set.options {
                for id in option {
                    if alternatives
                        .iter()
                        .any(|alternative| alternative.contains(id))
                        && seen.insert(id.clone())
                    {
                        out.push(id.clone());
                    }
                }
            }
        }
    }

    for credential in &query.credentials {
        let Some(id) = credential.id() else {
            continue;
        };
        if alternatives
            .iter()
            .any(|alternative| alternative.contains(id))
            && seen.insert(id.to_string())
        {
            out.push(id.to_string());
        }
    }

    out
}

fn decompose_slots(alternatives: &[Config], id_order: &[String]) -> Option<Vec<SlotSpec>> {
    if alternatives.is_empty() {
        return Some(Vec::new());
    }

    let mut cooccurs = FxHashSet::default();
    for alternative in alternatives {
        for left in alternative {
            for right in alternative {
                if left < right {
                    cooccurs.insert((left.clone(), right.clone()));
                }
            }
        }
    }

    let ids = id_order
        .iter()
        .filter(|id| {
            alternatives
                .iter()
                .any(|alternative| alternative.contains(*id))
        })
        .cloned()
        .collect::<Vec<_>>();
    let mut slots = Vec::<Vec<String>>::new();
    decompose_slots_inner(&ids, alternatives, &cooccurs, 0, &mut slots)
}

fn decompose_slots_inner(
    ids: &[String],
    alternatives: &[Config],
    cooccurs: &FxHashSet<(String, String)>,
    index: usize,
    slots: &mut Vec<Vec<String>>,
) -> Option<Vec<SlotSpec>> {
    if index == ids.len() {
        return slots_match_alternatives(slots, alternatives);
    }

    let id = &ids[index];
    for slot_index in 0..slots.len() {
        if slots[slot_index]
            .iter()
            .any(|existing| ids_cooccur(id, existing, cooccurs))
        {
            continue;
        }
        slots[slot_index].push(id.clone());
        if let Some(result) = decompose_slots_inner(ids, alternatives, cooccurs, index + 1, slots) {
            return Some(result);
        }
        slots[slot_index].pop();
    }

    slots.push(vec![id.clone()]);
    let result = decompose_slots_inner(ids, alternatives, cooccurs, index + 1, slots);
    slots.pop();
    result
}

fn ids_cooccur(left: &str, right: &str, cooccurs: &FxHashSet<(String, String)>) -> bool {
    if left < right {
        cooccurs.contains(&(left.to_string(), right.to_string()))
    } else {
        cooccurs.contains(&(right.to_string(), left.to_string()))
    }
}

fn slots_match_alternatives(
    slots: &[Vec<String>],
    alternatives: &[Config],
) -> Option<Vec<SlotSpec>> {
    let observed = alternatives.iter().cloned().collect::<BTreeSet<_>>();
    let mut specs = Vec::new();
    let mut choices = Vec::new();

    for slot in slots {
        let optional = alternatives
            .iter()
            .any(|alternative| !slot.iter().any(|id| alternative.contains(id)));
        choices.push((slot.clone(), optional));
        specs.push(SlotSpec {
            ids: slot.clone(),
            optional,
        });
    }

    let mut generated = BTreeSet::new();
    generate_slot_products(&choices, 0, Config::new(), &mut generated);
    (generated == observed).then_some(specs)
}

fn generate_slot_products(
    choices: &[(Vec<String>, bool)],
    index: usize,
    current: Config,
    out: &mut BTreeSet<Config>,
) {
    if index == choices.len() {
        out.insert(current);
        return;
    }

    let (ids, optional) = &choices[index];
    for id in ids {
        let mut next = current.clone();
        next.insert(id.clone());
        generate_slot_products(choices, index + 1, next, out);
    }
    if *optional {
        generate_slot_products(choices, index + 1, current, out);
    }
}

fn build_unfactored_presentation_sets<C>(
    alternative_maps: Vec<BTreeMap<String, SelectionEntry<C>>>,
) -> Vec<PresentationSet<C>>
where
    C: Clone + Eq + std::hash::Hash,
{
    alternative_maps
        .into_iter()
        .map(|alternative| {
            alternative
                .into_values()
                .map(|entry| {
                    let alternatives = build_slot_alternatives(&[SlotEntry {
                        selections: entry.selections,
                    }]);
                    SetAlternative { alternatives }
                })
                .collect()
        })
        .collect()
}

fn build_slot_alternatives<C>(entries: &[SlotEntry<C>]) -> Vec<CredentialSelection<C>>
where
    C: Clone + Eq + std::hash::Hash,
{
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();
    for entry in entries {
        for selection in &entry.selections {
            let key = (
                selection.dcql_id.clone(),
                claims_key(&selection.selected_claims),
                selection.credential_id.clone(),
                selection.transaction_data_ids.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            out.push(selection.clone());
        }
    }

    out
}

fn claims_key(claims: &[ClaimsQuery]) -> String {
    serde_json::to_string(claims).unwrap_or_default()
}

fn match_query<S>(
    store: &S,
    query: &CredentialQuery,
) -> Result<QueryMatches<S::CredentialRef>, PlanError>
where
    S: CredentialStore,
    S::CredentialRef: Clone,
{
    let format = query.format();
    if matches!(format, CredentialFormat::Unknown) {
        return Err(PlanError::InvalidQuery(
            "unsupported credential format in dcql_query.credentials entry".to_string(),
        ));
    }
    let common = query.common().ok_or_else(|| {
        PlanError::InvalidQuery(
            "unsupported credential format in dcql_query.credentials entry".to_string(),
        )
    })?;
    let meta = query.meta().ok_or_else(|| {
        PlanError::InvalidQuery(
            "unsupported credential format in dcql_query.credentials entry".to_string(),
        )
    })?;
    let candidates = store
        .list_credentials(Some(format))
        .into_iter()
        .filter(|cred| meta_matches(store, cred, query))
        .collect();

    Ok(QueryMatches {
        id: common.id.clone(),
        format,
        meta,
        multiple: common.multiple.unwrap_or(false),
        require_holder_binding: common.require_cryptographic_holder_binding.unwrap_or(true),
        trusted_authorities: common.trusted_authorities.clone(),
        selected_claims: Vec::new(),
        credentials: candidates,
    })
}

fn meta_matches<S>(store: &S, cred: &S::CredentialRef, query: &CredentialQuery) -> bool
where
    S: CredentialStore + ?Sized,
{
    if query
        .trusted_authorities()
        .is_some_and(|trusted_authorities| {
            !store.matches_trusted_authorities(cred, trusted_authorities)
        })
    {
        return false;
    }

    if query.require_cryptographic_holder_binding().unwrap_or(true)
        && query.format() == CredentialFormat::DcSdJwt
        && !store.supports_holder_binding(cred)
    {
        return false;
    }

    match query.meta() {
        Some(Meta::IsoMdoc(meta)) => store.has_doctype(cred, &meta.doctype_value),
        Some(Meta::SdJwtVc(meta)) => match meta.vct_values.as_deref() {
            None => true,
            Some(values) => values.iter().any(|v| store.has_vct(cred, v)),
        },
        None => false,
    }
}

fn match_claim_selection<S>(
    store: &S,
    query: &CredentialQuery,
    candidates: Vec<S::CredentialRef>,
) -> (Vec<ClaimsQuery>, Vec<S::CredentialRef>)
where
    S: CredentialStore,
    S::CredentialRef: Clone,
{
    let Some(claims) = query.claims() else {
        return (Vec::new(), candidates);
    };
    let claims = dedupe_claims_by_path(claims);

    let Some(claim_sets) = query.claim_sets() else {
        let filtered = filter_candidates(store, &claims, &candidates);
        return (claims, filtered);
    };

    let claims_by_id = map_claims_by_id(&claims);
    let mut saw_valid_claim_set = false;

    for option in claim_sets {
        let mut selected = Vec::new();
        for id in option {
            let Some(claim) = claims_by_id.get(id) else {
                selected.clear();
                break;
            };
            selected.push((*claim).clone());
        }
        if selected.is_empty() {
            continue;
        }
        saw_valid_claim_set = true;
        let filtered = filter_candidates(store, &selected, &candidates);
        if !filtered.is_empty() {
            return (selected, filtered);
        }
    }

    if !saw_valid_claim_set {
        let filtered = filter_candidates(store, &claims, &candidates);
        return (claims, filtered);
    }

    (Vec::new(), Vec::new())
}

fn map_claims_by_id(claims: &[ClaimsQuery]) -> BTreeMap<String, &ClaimsQuery> {
    let mut map = BTreeMap::new();
    for claim in claims {
        let Some(id) = claim.id() else {
            // Skip claims without an id — claim_sets cannot reference them.
            continue;
        };
        // First occurrence wins; duplicates are silently ignored.
        map.entry(id.to_string()).or_insert(claim);
    }
    map
}

fn filter_candidates<S>(
    store: &S,
    claims: &[ClaimsQuery],
    candidates: &[S::CredentialRef],
) -> Vec<S::CredentialRef>
where
    S: CredentialStore,
    S::CredentialRef: Clone,
{
    candidates
        .iter()
        .filter(|cred| claims.iter().all(|claim| claim_matches(store, cred, claim)))
        .cloned()
        .collect()
}

fn dedupe_claims_by_path(claims: &[ClaimsQuery]) -> Vec<ClaimsQuery> {
    let mut seen_paths = FxHashSet::default();
    let mut out = Vec::new();
    for claim in claims {
        if claim.path.is_empty() {
            continue;
        }
        if seen_paths.insert(claim.path.clone()) {
            out.push(claim.clone());
        }
    }
    out
}

pub(crate) fn match_claims<S>(
    store: &S,
    cred: &S::CredentialRef,
    query: &CredentialQuery,
) -> Option<Vec<ClaimsQuery>>
where
    S: CredentialStore + ?Sized,
{
    let Some(claims) = query.claims() else {
        return Some(Vec::new());
    };
    let claims = dedupe_claims_by_path(claims);
    let Some(claim_sets) = query.claim_sets() else {
        return claims
            .iter()
            .all(|claim| claim_matches(store, cred, claim))
            .then_some(claims);
    };

    let claims_by_id = map_claims_by_id(&claims);
    let mut saw_valid_claim_set = false;

    for option in claim_sets {
        let mut selected = Vec::new();
        for id in option {
            let Some(claim) = claims_by_id.get(id) else {
                selected.clear();
                break;
            };
            selected.push((*claim).clone());
        }
        if selected.is_empty() {
            continue;
        }
        saw_valid_claim_set = true;
        if selected
            .iter()
            .all(|claim| claim_matches(store, cred, claim))
        {
            return Some(selected);
        }
    }

    if !saw_valid_claim_set {
        return claims
            .iter()
            .all(|claim| claim_matches(store, cred, claim))
            .then_some(claims);
    }

    None
}

fn claim_matches<S>(store: &S, cred: &S::CredentialRef, claim: &ClaimsQuery) -> bool
where
    S: CredentialStore + ?Sized,
{
    if claim.path.is_empty() {
        return false;
    }

    if !store.has_claim_path(cred, &claim.path) {
        return false;
    }

    let Some(values) = &claim.values else {
        return true;
    };

    matches!(
        store.match_claim_value(cred, &claim.path, values),
        ValueMatch::Match
    )
}

type Config = BTreeSet<String>;

fn build_configs<C>(
    query: &DcqlQuery,
    matches_by_id: &BTreeMap<String, QueryMatches<C>>,
    options: &PlanOptions,
) -> Result<Vec<Config>, PlanError>
where
    C: Clone,
{
    let Some(credential_sets) = &query.credential_sets else {
        let mut all = Config::new();
        for credential_query in &query.credentials {
            if credential_query.format() == CredentialFormat::Unknown {
                continue;
            }
            let Some(query_id) = credential_query.id() else {
                continue;
            };
            if all.contains(query_id) {
                continue;
            }
            let Some(matches) = matches_by_id.get(query_id) else {
                return Err(PlanError::Unsatisfied);
            };
            if matches.credentials.is_empty() {
                return Err(PlanError::Unsatisfied);
            }
            all.insert(query_id.to_owned());
        }
        if all.is_empty() {
            return Err(PlanError::Unsatisfied);
        }
        return Ok(vec![all]);
    };

    let (required, optional): (Vec<_>, Vec<_>) =
        credential_sets.iter().partition(|set| set.required);

    let required_options = required
        .iter()
        .map(|set| feasible_options(set, matches_by_id, options.credential_set_option_mode))
        .collect::<Vec<_>>();

    if required_options.iter().any(|opts| opts.is_empty()) {
        return Err(PlanError::Unsatisfied);
    }

    let mut configs = if required_options.is_empty() {
        vec![Config::new()]
    } else {
        cartesian_union(&required_options)
    };

    for set in optional {
        let options_for_set =
            feasible_options(set, matches_by_id, options.credential_set_option_mode);
        if options_for_set.is_empty() {
            continue;
        }
        configs = match options.optional_credential_sets_mode {
            OptionalCredentialSetsMode::PreferPresent => {
                expand_optional_prefer_present(configs, options_for_set)
            }
            OptionalCredentialSetsMode::PreferAbsent => {
                expand_optional_prefer_absent(configs, options_for_set)
            }
            OptionalCredentialSetsMode::AlwaysPresentIfSatisfiable => {
                include_optional_only(configs, options_for_set)
            }
        };
    }

    Ok(normalize_configs(configs))
}

fn feasible_options<C>(
    set: &CredentialSetQuery,
    matches_by_id: &BTreeMap<String, QueryMatches<C>>,
    mode: CredentialSetOptionMode,
) -> Vec<Config>
where
    C: Clone,
{
    let mut out = Vec::new();
    for option in &set.options {
        if option.is_empty() {
            continue;
        }
        let feasible = option.iter().all(|id| {
            matches_by_id
                .get(id)
                .map(|matches| !matches.credentials.is_empty())
                .unwrap_or(false)
        });
        if !feasible {
            continue;
        }
        out.push(option.iter().cloned().collect());
        if matches!(mode, CredentialSetOptionMode::FirstSatisfiableOnly) {
            break;
        }
    }
    out
}

fn cartesian_union(options: &[Vec<Config>]) -> Vec<Config> {
    let mut acc = vec![Config::new()];
    for set_options in options {
        let mut next = Vec::new();
        for base in &acc {
            for option in set_options {
                let mut combined = base.clone();
                combined.extend(option.iter().cloned());
                next.push(combined);
            }
        }
        acc = next;
    }
    acc
}

fn include_optional_only(configs: Vec<Config>, options: Vec<Config>) -> Vec<Config> {
    let mut out = Vec::new();
    for config in configs {
        for option in &options {
            let mut combined = config.clone();
            combined.extend(option.iter().cloned());
            out.push(combined);
        }
    }
    out
}

fn expand_optional_prefer_present(configs: Vec<Config>, options: Vec<Config>) -> Vec<Config> {
    let mut out = Vec::new();
    for config in configs {
        for option in &options {
            let mut combined = config.clone();
            combined.extend(option.iter().cloned());
            if combined != config {
                out.push(combined);
            }
        }
        out.push(config);
    }
    out
}

fn expand_optional_prefer_absent(configs: Vec<Config>, options: Vec<Config>) -> Vec<Config> {
    let mut out = Vec::new();
    for config in configs {
        out.push(config.clone());
        for option in &options {
            let mut combined = config.clone();
            combined.extend(option.iter().cloned());
            if combined != config {
                out.push(combined);
            }
        }
    }
    out
}

fn order_config_ids(query: &DcqlQuery, config: &Config) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = FxHashSet::default();

    if let Some(credential_sets) = &query.credential_sets {
        for set in credential_sets {
            let Some(option) = set
                .options
                .iter()
                .find(|option| option.iter().all(|id| config.contains(id)))
            else {
                continue;
            };

            for id in option {
                if seen.insert(id.clone()) {
                    ordered.push(id.clone());
                }
            }
        }
    }

    for credential_query in &query.credentials {
        let Some(id) = credential_query.id() else {
            continue;
        };
        if config.contains(id) && seen.insert(id.to_string()) {
            ordered.push(id.to_string());
        }
    }

    for id in config {
        if seen.insert(id.clone()) {
            ordered.push(id.clone());
        }
    }

    ordered
}

fn normalize_configs(configs: Vec<Config>) -> Vec<Config> {
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();
    for config in configs {
        if seen.insert(config.clone()) {
            out.push(config);
        }
    }
    out
}

struct SelectionBuildContext<'a, S>
where
    S: CredentialStore + ?Sized,
{
    store: &'a S,
    options: &'a PlanOptions,
    transaction_data: &'a [TransactionData],
    ts12_indices: &'a [usize],
    assignment: &'a TransactionAssignment<S::CredentialRef>,
}

fn selections_for_query<S>(
    ctx: &SelectionBuildContext<'_, S>,
    id: &str,
    selected_claims: Vec<ClaimsQuery>,
    credentials: Vec<S::CredentialRef>,
) -> Vec<CredentialSelection<S::CredentialRef>>
where
    S: CredentialStore + ?Sized,
    S::CredentialRef: Clone,
{
    credentials
        .into_iter()
        .filter_map(|credential| {
            let mut transaction_data_ids = ctx
                .assignment
                .transaction_credential_ids
                .iter()
                .filter_map(|(idx, selected_id)| (selected_id == id).then_some(*idx))
                .collect::<Vec<_>>();

            match select_ts12_transaction_data(
                ctx.store,
                ctx.options,
                id,
                &credential,
                ctx.transaction_data,
                ctx.ts12_indices,
            ) {
                Ts12Selection::None => {}
                Ts12Selection::Selected(idx) => transaction_data_ids.push(idx),
                Ts12Selection::Incompatible => return None,
            }
            transaction_data_ids.sort_unstable();

            Some(CredentialSelection {
                dcql_id: id.to_string(),
                credential_id: Some(credential),
                selected_claims: selected_claims.clone(),
                transaction_data_ids,
            })
        })
        .collect()
}

enum Ts12Selection {
    None,
    Selected(usize),
    Incompatible,
}

fn select_ts12_transaction_data<S>(
    store: &S,
    options: &PlanOptions,
    id: &str,
    credential: &S::CredentialRef,
    transaction_data: &[TransactionData],
    ts12_indices: &[usize],
) -> Ts12Selection
where
    S: CredentialStore + ?Sized,
{
    let mut targeted = false;
    for index in ts12_indices {
        let Some(data) = transaction_data.get(*index) else {
            continue;
        };
        if !options.is_ts12_transaction_data_type(&data.r#type)
            || !data
                .credential_ids
                .iter()
                .any(|credential_id| credential_id == id)
        {
            continue;
        }
        targeted = true;
        if store.can_sign_transaction_data(credential, data) {
            return Ts12Selection::Selected(*index);
        }
    }

    if targeted {
        Ts12Selection::Incompatible
    } else {
        Ts12Selection::None
    }
}

#[derive(Debug, Clone)]
struct TransactionAssignment<C> {
    transaction_credential_ids: BTreeMap<usize, String>,
    domains: BTreeMap<String, Vec<C>>,
}

fn enumerate_transaction_assignments<S>(
    store: &S,
    config: &Config,
    matches_by_id: &BTreeMap<String, QueryMatches<S::CredentialRef>>,
    transaction_data: &[TransactionData],
    transaction_data_indices: &[usize],
) -> Vec<TransactionAssignment<S::CredentialRef>>
where
    S: CredentialStore,
    S::CredentialRef: Clone,
{
    let mut domains = BTreeMap::new();
    for id in config {
        let Some(matches) = matches_by_id.get(id) else {
            return Vec::new();
        };
        if matches.credentials.is_empty() {
            return Vec::new();
        }
        domains.insert(id.clone(), matches.credentials.clone());
    }

    if transaction_data_indices.is_empty() {
        return vec![TransactionAssignment {
            transaction_credential_ids: BTreeMap::new(),
            domains,
        }];
    }

    let mut options_by_td: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for &td_idx in transaction_data_indices {
        let Some(data) = transaction_data.get(td_idx) else {
            return Vec::new();
        };
        let mut options = Vec::new();
        for id in &data.credential_ids {
            if !config.contains(id) {
                continue;
            }
            let Some(domain) = domains.get(id) else {
                continue;
            };
            if domain
                .iter()
                .any(|cred| store.can_sign_transaction_data(cred, data))
            {
                options.push(id.clone());
            }
        }
        if options.is_empty() {
            return Vec::new();
        }
        options_by_td.insert(td_idx, options);
    }

    let mut order = transaction_data_indices.to_vec();
    order.sort_by_key(|idx| options_by_td.get(idx).map(|set| set.len()).unwrap_or(0));

    let mut transaction_credential_ids = BTreeMap::new();
    let mut out = Vec::new();
    let mut ctx = TransactionBacktrack {
        store,
        transaction_data,
        options_by_td: &options_by_td,
        order: &order,
        domains: &mut domains,
        transaction_credential_ids: &mut transaction_credential_ids,
        out: &mut out,
    };
    let _ = backtrack_transaction_assignments(&mut ctx, 0);
    out
}

struct TransactionBacktrack<'a, S: CredentialStore + ?Sized> {
    store: &'a S,
    transaction_data: &'a [TransactionData],
    options_by_td: &'a BTreeMap<usize, Vec<String>>,
    order: &'a [usize],
    domains: &'a mut BTreeMap<String, Vec<S::CredentialRef>>,
    transaction_credential_ids: &'a mut BTreeMap<usize, String>,
    out: &'a mut Vec<TransactionAssignment<S::CredentialRef>>,
}

fn backtrack_transaction_assignments<S>(
    ctx: &mut TransactionBacktrack<'_, S>,
    depth: usize,
) -> Option<()>
where
    S: CredentialStore + ?Sized,
    S::CredentialRef: Clone,
{
    if depth == ctx.order.len() {
        ctx.out.push(TransactionAssignment {
            transaction_credential_ids: ctx.transaction_credential_ids.clone(),
            domains: ctx.domains.clone(),
        });
        return Some(());
    }

    let &td_idx = ctx.order.get(depth)?;
    let td = ctx.transaction_data.get(td_idx)?;
    let options = ctx.options_by_td.get(&td_idx)?;

    for id in options {
        let Some(current_domain) = ctx.domains.get(id).cloned() else {
            continue;
        };

        let filtered_domain = current_domain
            .iter()
            .filter(|cred| ctx.store.can_sign_transaction_data(cred, td))
            .cloned()
            .collect::<Vec<_>>();
        if filtered_domain.is_empty() {
            continue;
        }

        ctx.domains.insert(id.clone(), filtered_domain);
        ctx.transaction_credential_ids.insert(td_idx, id.clone());

        backtrack_transaction_assignments(ctx, depth + 1)?;

        ctx.transaction_credential_ids.remove(&td_idx);
        ctx.domains.insert(id.clone(), current_domain);
    }

    Some(())
}

/// Helper to build a claims path pointer from string components.
pub fn pointer_from_strings(path: &[&str]) -> ClaimsPathPointer {
    path.iter()
        .map(|s| PathElement::String((*s).to_string()))
        .collect()
}
