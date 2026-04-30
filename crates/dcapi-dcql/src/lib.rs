#![doc = include_str!("../README.md")]
mod models;
mod path;
mod planner;
mod store;

pub use android_credman::CredentialReader;
pub use models::*;
pub use path::{
    ClaimsPathPointer, PathElement, PathError, is_mdoc_path, path_matches, select_nodes,
};
pub use planner::{
    CredentialSelection, CredentialSetOptionMode, DEFAULT_TS12_PREFIX, DcqlOutput,
    OptionalCredentialSetsMode, PlanError, PlanOptions, PresentationSet, QueryMatches,
    SetAlternative, plan_selection, pointer_from_strings,
};
pub use store::{CredentialFormat, CredentialStore, ValueMatch};
