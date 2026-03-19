use crate::models::{
    ClaimsQuery, CredentialQuery, CredentialSetQuery, DcqlQuery, Meta, TransactionData,
    TrustedAuthority,
};
use crate::path::{ClaimsPathPointer, PathElement};
use crate::store::{CredentialFormat, CredentialStore, ValueMatch};
use rustc_hash::{FxHashMap, FxHashSet};
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

/// Planner configuration knobs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PlanOptions {
    /// Option-selection policy for each Credential Set Query.
    pub credential_set_option_mode: CredentialSetOptionMode,
    /// Inclusion policy for optional Credential Set Queries.
    pub optional_credential_sets_mode: OptionalCredentialSetsMode,
}

impl Default for PlanOptions {
    fn default() -> Self {
        Self {
            credential_set_option_mode: CredentialSetOptionMode::AllSatisfiable,
            optional_credential_sets_mode: OptionalCredentialSetsMode::PreferPresent,
        }
    }
}

/// One entry in an inner selection set.
#[derive(Debug, Clone)]
struct SelectionEntry<C> {
    /// Query context and selectable credential candidates for this id.
    query: QueryMatches<C>,
    /// Transaction data indices that are bound to this credential id in this alternative.
    transaction_data_indices: Vec<usize>,
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
}

/// One slot inside a presentation set.
///
/// The slot exposes multiple alternative credentials (potentially from
/// different dcql ids). All alternatives in the slot must share the same
/// transaction-data indices.
#[derive(Debug, Clone)]
pub struct SetAlternative<C> {
    /// Alternative credentials for this slot.
    pub alternatives: Vec<CredentialSelection<C>>,
    /// Transaction-data indices bound to this slot.
    pub transaction_data_ids: Vec<usize>,
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
    let mut matches_by_id = BTreeMap::new();
    let mut query_by_id = BTreeMap::new();
    for credential_query in &query.credentials {
        let matches = match match_query(store, credential_query) {
            Ok(m) => m,
            Err(PlanError::InvalidQuery(_)) if credential_query.format() == CredentialFormat::Unknown => {
                // Skip credentials with unsupported formats so that
                // credential-set options referencing them are simply pruned.
                continue;
            }
            Err(e) => return Err(e),
        };
        let query_id = credential_query
            .id()
            .ok_or_else(|| {
                PlanError::InvalidQuery(
                    "internal invariant violated: dcql_query.credentials entry missing id after validation"
                        .to_string(),
                )
            })?;
        matches_by_id.insert(query_id.to_owned(), matches);
        query_by_id.insert(query_id.to_owned(), credential_query);
    }

    let configs = build_configs(query, &matches_by_id, options)?;
    if configs.is_empty() {
        return Err(PlanError::Unsatisfied);
    }

    let transaction_data = transaction_data.unwrap_or_default();

    let mut alternatives = Vec::new();
    for config in configs {
        let assignments =
            enumerate_transaction_assignments(store, &config, &matches_by_id, transaction_data);
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
                let Some(query_definition) = query_by_id.get(id) else {
                    continue;
                };
                let (selected_claims, filtered_domain) =
                    match_claim_selection(store, query_definition, domain)?;
                if filtered_domain.is_empty() {
                    continue;
                }
                query_match.selected_claims = selected_claims;
                query_match.credentials = filtered_domain;

                let transaction_data_indices = assignment
                    .transaction_credential_ids
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, selected_id)| (selected_id == id).then_some(idx))
                    .collect();

                entries.push(SelectionEntry {
                    query: query_match,
                    transaction_data_indices,
                });
            }

            if entries.len() != config.len()
                || entries
                    .iter()
                    .any(|entry| entry.query.credentials.is_empty())
            {
                continue;
            }

            if assignment.transaction_credential_ids.len() != transaction_data.len() {
                continue;
            }
            alternatives.push(SelectionAlternative { entries });
        }
    }

    if alternatives.is_empty() {
        return Err(PlanError::Unsatisfied);
    }

    Ok(build_presentation_sets(query, alternatives))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SlotKey {
    SimpleSet {
        set_index: usize,
        transaction_data_ids: Vec<usize>,
    },
    QueryId {
        id: String,
        transaction_data_ids: Vec<usize>,
    },
}

impl SlotKey {
    fn transaction_data_ids(&self) -> &[usize] {
        match self {
            SlotKey::SimpleSet {
                transaction_data_ids,
                ..
            }
            | SlotKey::QueryId {
                transaction_data_ids,
                ..
            } => transaction_data_ids.as_slice(),
        }
    }

    fn simple_set_index(&self) -> Option<usize> {
        match self {
            SlotKey::SimpleSet { set_index, .. } => Some(*set_index),
            SlotKey::QueryId { .. } => None,
        }
    }
}

#[derive(Debug, Clone)]
struct SlotEntry<C> {
    dcql_id: String,
    selected_claims: Vec<ClaimsQuery>,
    credentials: Vec<C>,
}

#[derive(Debug, Clone)]
struct SlotGroup<C> {
    slot_keys: Vec<SlotKey>,
    slot_entries: BTreeMap<SlotKey, Vec<SlotEntry<C>>>,
}

#[derive(Debug, Clone)]
struct SlotCluster<C> {
    required_key: Vec<SlotKey>,
    slot_entries: BTreeMap<SlotKey, Vec<SlotEntry<C>>>,
    optional_slot_keys: BTreeMap<usize, SlotKey>,
    optional_slot_counts: BTreeMap<SlotKey, usize>,
    group_count: usize,
}

fn build_presentation_sets<C>(
    query: &DcqlQuery,
    alternatives: Vec<SelectionAlternative<C>>,
) -> DcqlOutput<C>
where
    C: Clone + Eq + std::hash::Hash,
{
    let (simple_set_by_id, optional_simple_sets) = analyze_simple_sets(query);
    let mut groups = Vec::<SlotGroup<C>>::new();
    let mut group_index = FxHashMap::<Vec<SlotKey>, usize>::default();

    for alternative in alternatives {
        let mut slot_map = Vec::<(SlotKey, SlotEntry<C>)>::new();
        for entry in alternative.entries {
            let mut transaction_data_indices = entry.transaction_data_indices.clone();
            transaction_data_indices.sort_unstable();

            let slot_key = if let Some(set_index) = simple_set_by_id.get(&entry.query.id) {
                SlotKey::SimpleSet {
                    set_index: *set_index,
                    transaction_data_ids: transaction_data_indices,
                }
            } else {
                SlotKey::QueryId {
                    id: entry.query.id.clone(),
                    transaction_data_ids: transaction_data_indices,
                }
            };

            slot_map.push((
                slot_key,
                SlotEntry {
                    dcql_id: entry.query.id.clone(),
                    selected_claims: entry.query.selected_claims.clone(),
                    credentials: entry.query.credentials.clone(),
                },
            ));
        }

        let slot_keys = slot_map.iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
        let group_idx = if let Some(index) = group_index.get(&slot_keys).copied() {
            index
        } else {
            let index = groups.len();
            groups.push(SlotGroup {
                slot_keys: slot_keys.clone(),
                slot_entries: BTreeMap::new(),
            });
            group_index.insert(slot_keys.clone(), index);
            index
        };

        let group = groups.get_mut(group_idx).expect("group index valid");
        for (slot_key, entry) in slot_map {
            group
                .slot_entries
                .entry(slot_key)
                .or_default()
                .push(entry);
        }
    }

    let mut clusters: Vec<SlotCluster<C>> = Vec::new();
    for group in groups {
        let (required_key, optional_map) = partition_slot_keys(&group.slot_keys, &optional_simple_sets);

        let mut merged = false;
        for cluster in &mut clusters {
            if cluster.required_key != required_key {
                continue;
            }
            if !can_merge_optional_slots(cluster, &optional_map) {
                continue;
            }
            merge_group_into_cluster(cluster, &group, &optional_map);
            merged = true;
            break;
        }

        if !merged {
            let mut cluster = SlotCluster {
                required_key,
                slot_entries: BTreeMap::new(),
                optional_slot_keys: BTreeMap::new(),
                optional_slot_counts: BTreeMap::new(),
                group_count: 0,
            };
            merge_group_into_cluster(&mut cluster, &group, &optional_map);
            clusters.push(cluster);
        }
    }

    let mut presentation_sets = Vec::new();
    for cluster in clusters {
        let mut slots = Vec::new();
        let ordered_keys = order_slot_keys(query, cluster.slot_entries.keys());
        for slot_key in ordered_keys {
            let entries = match cluster.slot_entries.get(&slot_key) {
                Some(entries) => entries,
                None => continue,
            };
            let mut alternatives = build_slot_alternatives(entries);
            if is_optional_slot(&slot_key, &optional_simple_sets)
                && cluster
                    .optional_slot_counts
                    .get(&slot_key)
                    .copied()
                    .unwrap_or(0)
                    < cluster.group_count
                && slot_key.transaction_data_ids().is_empty()
            {
                let dcql_id = alternatives
                    .first()
                    .map(|selection| selection.dcql_id.clone())
                    .unwrap_or_default();
                alternatives.push(CredentialSelection {
                    dcql_id,
                    credential_id: None,
                    selected_claims: Vec::new(),
                });
            }

            slots.push(SetAlternative {
                alternatives,
                transaction_data_ids: slot_key.transaction_data_ids().to_vec(),
            });
        }
        presentation_sets.push(slots);
    }

    DcqlOutput { presentation_sets }
}

fn analyze_simple_sets(query: &DcqlQuery) -> (BTreeMap<String, usize>, BTreeSet<usize>) {
    let mut by_id = BTreeMap::new();
    let mut optional = BTreeSet::new();

    let Some(credential_sets) = &query.credential_sets else {
        return (by_id, optional);
    };

    for (idx, set) in credential_sets.iter().enumerate() {
        let non_empty_options = set.options.iter().filter(|opt| !opt.is_empty()).collect::<Vec<_>>();
        if non_empty_options.is_empty() {
            continue;
        }
        let simple = non_empty_options.iter().all(|opt| opt.len() == 1);
        if !simple {
            continue;
        }
        if !set.required {
            optional.insert(idx);
        }
        for option in non_empty_options {
            if let Some(id) = option.first() {
                by_id.insert(id.clone(), idx);
            }
        }
    }

    (by_id, optional)
}

fn partition_slot_keys(
    slot_keys: &[SlotKey],
    optional_simple_sets: &BTreeSet<usize>,
) -> (Vec<SlotKey>, BTreeMap<usize, SlotKey>) {
    let mut required = Vec::new();
    let mut optional = BTreeMap::new();
    for key in slot_keys {
        if is_optional_slot(key, optional_simple_sets) {
            if let Some(set_index) = key.simple_set_index() {
                optional.insert(set_index, key.clone());
            }
        } else {
            required.push(key.clone());
        }
    }
    (required, optional)
}

fn is_optional_slot(key: &SlotKey, optional_simple_sets: &BTreeSet<usize>) -> bool {
    key.simple_set_index()
        .is_some_and(|idx| optional_simple_sets.contains(&idx))
}

fn order_slot_keys<'a, I>(query: &DcqlQuery, keys: I) -> Vec<SlotKey>
where
    I: IntoIterator<Item = &'a SlotKey>,
{
    let credential_index = query
        .credentials
        .iter()
        .enumerate()
        .filter_map(|(idx, cred)| cred.id().map(|id| (id.to_string(), idx)))
        .collect::<BTreeMap<_, _>>();

    let mut ordered = keys.into_iter().cloned().collect::<Vec<_>>();
    ordered.sort_by_key(|key| match key {
        SlotKey::SimpleSet {
            set_index,
            transaction_data_ids,
        } => (0u8, *set_index, transaction_data_ids.clone(), String::new()),
        SlotKey::QueryId {
            id,
            transaction_data_ids,
        } => (
            1u8,
            *credential_index.get(id).unwrap_or(&usize::MAX),
            transaction_data_ids.clone(),
            id.clone(),
        ),
    });
    ordered
}

fn can_merge_optional_slots<C>(
    cluster: &SlotCluster<C>,
    optional_map: &BTreeMap<usize, SlotKey>,
) -> bool {
    for (set_index, slot_key) in optional_map {
        if let Some(existing) = cluster.optional_slot_keys.get(set_index) {
            if existing != slot_key {
                return false;
            }
        } else if !slot_key.transaction_data_ids().is_empty() {
            return false;
        }
    }
    for (set_index, existing) in &cluster.optional_slot_keys {
        if !optional_map.contains_key(set_index) && !existing.transaction_data_ids().is_empty() {
            return false;
        }
    }
    true
}

fn merge_group_into_cluster<C>(
    cluster: &mut SlotCluster<C>,
    group: &SlotGroup<C>,
    optional_map: &BTreeMap<usize, SlotKey>,
) where
    C: Clone + Eq + std::hash::Hash,
{
    cluster.group_count += 1;
    for (slot_key, entries) in &group.slot_entries {
        cluster
            .slot_entries
            .entry(slot_key.clone())
            .or_default()
            .extend(entries.clone());
    }

    for (set_index, slot_key) in optional_map {
        cluster
            .optional_slot_keys
            .entry(*set_index)
            .or_insert(slot_key.clone());
        let count = cluster.optional_slot_counts.entry(slot_key.clone()).or_insert(0);
        *count += 1;
    }
}

fn build_slot_alternatives<C>(entries: &[SlotEntry<C>]) -> Vec<CredentialSelection<C>>
where
    C: Clone + Eq + std::hash::Hash,
{
    let mut seen = FxHashSet::default();
    let mut out = Vec::new();
    for entry in entries {
        let claims_key = claims_key(&entry.selected_claims);
        for credential in &entry.credentials {
            let key = (entry.dcql_id.clone(), claims_key.clone(), credential.clone());
            if !seen.insert(key.clone()) {
                continue;
            }
            out.push(CredentialSelection {
                dcql_id: entry.dcql_id.clone(),
                credential_id: Some(credential.clone()),
                selected_claims: entry.selected_claims.clone(),
            });
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
    S: CredentialStore,
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
) -> Result<(Vec<ClaimsQuery>, Vec<S::CredentialRef>), PlanError>
where
    S: CredentialStore,
    S::CredentialRef: Clone,
{
    let Some(claims) = query.claims() else {
        return Ok((Vec::new(), candidates));
    };
    let claims = dedupe_claims_by_path(claims);

    let Some(claim_sets) = query.claim_sets() else {
        let filtered = filter_candidates(store, &claims, &candidates);
        return Ok((claims, filtered));
    };

    let Some(query_id) = query.id() else {
        return Err(PlanError::InvalidQuery(
            "internal invariant violated: dcql_query.credentials entry missing id during claim-set selection"
                .to_string(),
        ));
    };
    let claims_by_id = map_claims_by_id(query_id, &claims)?;

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
        let filtered = filter_candidates(store, &selected, &candidates);
        if !filtered.is_empty() {
            return Ok((selected, filtered));
        }
    }

    Ok((Vec::new(), Vec::new()))
}

fn map_claims_by_id<'a>(
    query_id: &str,
    claims: &'a [ClaimsQuery],
) -> Result<BTreeMap<String, &'a ClaimsQuery>, PlanError> {
    let mut map = BTreeMap::new();
    for claim in claims {
        let Some(id) = claim.id() else {
            return Err(PlanError::InvalidQuery(format!(
                "claims missing id: {query_id}"
            )));
        };
        if map.insert(id.to_string(), claim).is_some() {
            return Err(PlanError::InvalidQuery(format!(
                "duplicate claim id: {query_id}.{id}"
            )));
        }
    }
    Ok(map)
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

    let query_id = query.id()?;
    let claims_by_id = map_claims_by_id(query_id, &claims).ok()?;

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
        if selected
            .iter()
            .all(|claim| claim_matches(store, cred, claim))
        {
            return Some(selected);
        }
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
            let query_id = credential_query
                .id()
                .ok_or_else(|| {
                    PlanError::InvalidQuery(
                        "internal invariant violated: dcql_query.credentials entry missing id while building default config"
                            .to_string(),
                    )
                })?;
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

#[derive(Debug, Clone)]
struct TransactionAssignment<C> {
    transaction_credential_ids: Vec<String>,
    domains: BTreeMap<String, Vec<C>>,
}

fn enumerate_transaction_assignments<S>(
    store: &S,
    config: &Config,
    matches_by_id: &BTreeMap<String, QueryMatches<S::CredentialRef>>,
    transaction_data: &[TransactionData],
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

    if transaction_data.is_empty() {
        return vec![TransactionAssignment {
            transaction_credential_ids: Vec::new(),
            domains,
        }];
    }

    let mut options_by_td: Vec<Vec<String>> = Vec::with_capacity(transaction_data.len());
    for data in transaction_data {
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
        options_by_td.push(options);
    }

    let mut order: Vec<usize> = (0..transaction_data.len()).collect();
    order.sort_by_key(|idx| options_by_td.get(*idx).map(|set| set.len()).unwrap_or(0));

    let mut transaction_credential_ids = vec![String::new(); transaction_data.len()];
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
    options_by_td: &'a [Vec<String>],
    order: &'a [usize],
    domains: &'a mut BTreeMap<String, Vec<S::CredentialRef>>,
    transaction_credential_ids: &'a mut [String],
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
            transaction_credential_ids: ctx.transaction_credential_ids.to_vec(),
            domains: ctx.domains.clone(),
        });
        return Some(());
    }

    let &td_idx = ctx.order.get(depth)?;
    let td = ctx.transaction_data.get(td_idx)?;
    let options = ctx.options_by_td.get(td_idx)?;

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
        {
            let selected_id = ctx.transaction_credential_ids.get_mut(td_idx)?;
            *selected_id = id.clone();
        }

        backtrack_transaction_assignments(ctx, depth + 1)?;

        ctx.transaction_credential_ids.get_mut(td_idx)?.clear();
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
