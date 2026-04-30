# dcapi-dcql

## What it does

- Evaluates a `DcqlQuery` plus optional `transaction_data` against a wallet-provided
  `CredentialStore`.
- Returns a `SelectionPlan` structured for UI: outer alternatives, each containing one inner
  coherent set of credential entries and explicit transaction-data bindings.

## How to use

- Implement `CredentialStore` for your wallet.
- Implement `can_sign_transaction_data` if you support `transaction_data`.
- Deserialize a `DcqlQuery` from JSON and parse optional `transaction_data`.
- Call `plan_selection(query, transaction_data, store, options)`.
- Present one outer alternative at a time. For each inner `SelectionEntry`, the user picks
  credential(s) to present; `transaction_data` assignments in that alternative specify what is signed and by which `credential_id`.

Example:

```rust
use dcapi_dcql::{
    plan_selection, select_nodes, ClaimValue, ClaimsPathPointer, CredentialFormat, CredentialStore,
    DcqlQuery, PlanOptions, TransactionData, ValueMatch,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, Read};

#[derive(Clone)]
struct Cred {
    id: String,
    format: String,
    vct: Option<String>,
    holder_binding: bool,
    claims: Value,
}

struct Store {
    creds: HashMap<String, Cred>,
}

impl Store {
    fn get(&self, id: &str) -> &Cred {
        self.creds.get(id).expect("missing credential")
    }
}

impl CredentialStore for Store {
    type CredentialRef = String;
    type ReadError = io::Error;

    fn from_reader(reader: &mut dyn Read) -> Result<Self, Self::ReadError> {
        let mut _buf = String::new();
        reader.read_to_string(&mut _buf)?;
        Ok(Store {
            creds: HashMap::new(),
        })
    }

    fn list_credentials(&self, format: Option<CredentialFormat>) -> Vec<Self::CredentialRef> {
        self.creds
            .values()
            .filter(|c| {
                format
                    .map(|f| f == CredentialFormat::from(c.format.as_str()))
                    .unwrap_or(true)
            })
            .map(|c| c.id.clone())
            .collect()
    }

    fn format(&self, cred: &Self::CredentialRef) -> CredentialFormat {
        CredentialFormat::from(self.get(cred).format.as_str())
    }

    fn has_vct(&self, cred: &Self::CredentialRef, vct: &str) -> bool {
        self.get(cred).vct.as_deref() == Some(vct)
    }

    fn supports_holder_binding(&self, cred: &Self::CredentialRef) -> bool {
        self.get(cred).holder_binding
    }

    fn has_claim_path(&self, cred: &Self::CredentialRef, path: &ClaimsPathPointer) -> bool {
        let c = self.get(cred);
        select_nodes(&c.claims, path).is_ok()
    }

    fn match_claim_value(
        &self,
        cred: &Self::CredentialRef,
        path: &ClaimsPathPointer,
        expected_values: &[ClaimValue],
    ) -> ValueMatch {
        let c = self.get(cred);
        let Ok(nodes) = select_nodes(&c.claims, path) else {
            return ValueMatch::NoMatch;
        };
        if nodes.iter().any(|node| {
            expected_values.iter().any(|expected| match expected {
                ClaimValue::String(s) => node.as_str() == Some(s),
                ClaimValue::Integer(i) => node.as_i64() == Some(*i),
                ClaimValue::Boolean(b) => node.as_bool() == Some(*b),
            })
        }) {
            ValueMatch::Match
        } else {
            ValueMatch::NoMatch
        }
    }
}

let query_json = r#"
{
  "credentials": [{
    "id": "pid",
    "format": "dc+sd-jwt",
    "meta": { "vct_values": ["vct:pid"] },
    "claims": [
      { "id": "name", "path": ["name"] }
    ]
  }]
}
"#;

let query: DcqlQuery = serde_json::from_str(query_json).unwrap();
let transaction_data: Option<Vec<TransactionData>> = None;
let store = Store {
    creds: vec![Cred {
        id: "cred1".to_string(),
        format: "dc+sd-jwt".to_string(),
        vct: Some("vct:pid".to_string()),
        holder_binding: true,
        claims: json!({ "name": "Alice" }),
    }]
    .into_iter()
    .map(|c| (c.id.clone(), c))
    .collect(),
};

let plan = plan_selection(&query, transaction_data.as_deref(), &store, &PlanOptions::default()).unwrap();
for (set_idx, set) in plan.presentation_sets.iter().enumerate() {
    println!("presentation set #{set_idx}");
    for slot in set {
        for selection in &slot.alternatives {
            let cred_id = selection
                .credential_id
                .as_deref()
                .unwrap_or("<none>");
            println!("  tx data indices: {:?}", selection.transaction_data_ids);
            println!("  selection dcql_id={} credential_id={}", selection.dcql_id, cred_id);
        }
    }
}
```

## Rules it follows

- Unknown properties are ignored to stay extension-friendly.
- `credentials` must be non-empty.
- Credential ids and claim ids must use `[A-Za-z0-9_-]+` and be unique in their scope.
- Credential set option order is preserved.
- Planner options control:
  - all satisfiable credential-set options vs first satisfiable only,
  - optional-set behavior (`prefer present`, `prefer absent`, `always present if satisfiable`).
- `credential_sets`, `options`, `claims`, `claim_sets`, `values`, and `trusted_authorities`
  are rejected when present but empty.
- `claim_sets` selects the first satisfiable option and filters candidates to it.
- Duplicate claim paths are ignored (first occurrence wins).
- `transaction_data` is passed separately from `DcqlQuery`.
- `transaction_data` may be empty; an empty array is ignored.
- Transaction data compatibility semantics are delegated to `CredentialStore::can_sign_transaction_data`.
- Unknown credential ids in `transaction_data` are ignored during assignment; entries that cannot
  be assigned yield an Unsatisfied plan.
- Output alternatives make transaction-data assignment explicit (`transaction_data[i] -> credential_id`)
  and pre-filter candidate credentials so entry choices remain independent inside one alternative.
- For `dc+sd-jwt`, `meta.vct_values` is required and non-empty, and at least one value must match through
  `CredentialStore::has_vct`.
- For `dc+sd-jwt`, holder binding defaults to required.
- For `mso_mdoc`, `meta.doctype_value` is required and must match.
- Unknown credential query formats are rejected during validation.
- `values` matching is strict: only `ValueMatch::Match` is accepted.
