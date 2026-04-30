# dcapi-matcher

`dcapi-matcher` is a reusable matcher framework for:

- OpenID4VP (`dcql_query`)
- Android Credential Manager output building

## Purpose

The crate is designed so wallet projects only need to:

1. Define their credential package format.
2. Implement matching/display behavior through `MatcherStore`.

The framework handles request parsing, DCQL planning integration, and conversion to Credman
entry/set structures.

## Main API

- `match_dc_api_request(store, options)` (reads the DC API request JSON from Credman)
- `MatcherStore` (your package adapter trait)
- `MatcherResponse` (owned response; apply with `apply()`)
- `diagnostics` (collect and render execution diagnostics as Credman entries)
- `OpenId4VpConfig` (wallet-supported OpenID4VP capabilities)

## Package Decode Helpers

- `decode_json_package`

## Metadata Model

For each candidate credential, metadata passed to Credman includes only:

- `credential_id` (the DCQL credential query id)
- `transaction_data_indices` (indices into the request `transaction_data` array)

## Diagnostics Rendering

`dcapi-matcher` can collect execution diagnostics and render them as one final
credential set (`dcapi:diagnostics`).

- Scope lifecycle:
  - `match_dc_api_request` clears diagnostics at the start of matching.
  - the `#[dcapi_matcher]` macro flushes diagnostics at the end, after your matcher function returns (or panics).
- Severity filtering:
  - levels are `Trace`, `Debug`, `Info`, `Warn`, `Error`.
  - logging is disabled unless you call `diagnostics::set_level(...)` (for example via `MatcherStore::log_level`).
- Automatic recording:
  - matcher framework errors returned by `match_dc_api_request`
    (and package decode helpers) are recorded automatically.
  - panics caught by `#[dcapi_matcher]` are recorded as error diagnostics.
- Manual recording:
  - use `diagnostics::trace/debug/info/warn/error` to add app-specific diagnostics.

## OpenID Capability Support

The matcher currently enforces and/or supports the following OpenID behavior:

- OpenID4VP:
  - `dcql_query` evaluation (delegated to `dcapi-dcql`) with optional `transaction_data`.
  - supported request protocol variants are listed in `supported_request_protocols`.
  - supported response modes are listed in `supported_response_modes`.
  - supported response types are listed in `supported_response_types`.
  - supported query methods are listed in `supported_query_methods`.
  - supported extra request parameters are listed in `supported_request_parameters`.
  - unsupported OpenID parts are ignored and produce no match.
  - unknown request parameters are ignored.
  - `openid4vp-v1-signed` and `openid4vp-v1-multisigned` require decoded request objects;
    raw `request` objects are rejected (no JWS verification in this crate).
  - TS12 SCA transaction-data support:
    - built-in validation for `urn:eudi:sca:payment:1` and `urn:eudi:sca:generic:1`.
    - TS12 display is driven by credential-provided transaction metadata
      (`MatcherStore::ts12_transaction_metadata`) with localized claim labels and UI labels.
    - `MatcherStore::locales` must be provided for TS12; missing localized labels cause
      the matcher to return an error.
    - transaction fields are emitted as entry fields and appear before claim fields in string-id entries.
    - payment-style rendering is only used when a single TS12 entry provides payment payload data,
      and additional info is derived from localized transaction fields (no hardcoded labels).
    - optional `MatcherStore::format_ts12_value` hook lets wallets localize value codes
      (for example, recurrence frequency identifiers) without hardcoded strings in the matcher.

This split is intentional: `dcapi-matcher` provides deterministic matching and response shaping,
while network retrieval and cryptographic verification for signed flows can be layered on top by the integrator.

## Building and testing:
Thism will build the matcher and copy it over to the expo project
```sh
cargo build -p aptitude-consortium-dcapi-matcher --target wasm32-wasip1 --release && wasm-opt --enable-bulk-memory -Oz -o ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.opt.wasm ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.wasm && gzip -9 -c ./target/wasm32-wasip1/release/aptitude-consortium-dcapi-matcher.opt.wasm > ../expo-digital-credentials-api/android/src/main/assets/aptitude-consortium-matcher.wasm
```
