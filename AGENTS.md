# dcapi-matcher Operating Notes

**Purpose**
`dcapi-matcher` is a no_std + alloc WASM matcher for the Digital Credentials API. It parses DC API requests, matches credentials using DCQL/Presentation Definition/OpenID4VP, and emits Credman-compatible selection plans. If a protocol or feature is disabled in `MatcherOptions`, the matcher returns an empty response for that request.

**Reference Repos**
- `CMWallet` is a reference-only folder. Do not edit files under `CMWallet/`.

**TS12 Handling**
- No built-in TS12 transaction data types exist in this library. The credential package must provide fully resolved metadata for each supported transaction data type.
- The store must supply `Ts12TransactionMetadata` with full transaction data `type` URNs and payload-relative `claims`. Any `claims_uri` resolution or metadata merging must be done by the store.
- Claim display metadata is used only to decide whether TS12 value-type validation applies. It is not rendered as Credential Manager fields.
- Payment rendering is store-driven. Use `MatcherStore::ts12_payment_summary` to indicate a transaction should render as a payment entry. The matcher does not infer payment types.

**Transaction Data Warnings**
- Invalid `transaction_data` entries (bad base64, invalid JSON, missing `type`/`credential_ids`, or invalid TS12 payload shape) are dropped and logged as warnings.
- Errors tied to credential packages (e.g., invalid TS12 metadata) remove that credential from transaction data matching and emit warnings.
- If no valid `transaction_data` entries remain, the request yields an empty response.

**Logging and Errors**
- Runtime diagnostics are collected via the `dcapi_matcher::diagnostics` static logger. `flush_and_apply` renders logs as a Credman entry set when v2 is available, otherwise as individual string-id entries.
- The matcher avoids hardcoded UI strings. Only error/log messages are formatted in code; all display strings must come from credential metadata or store-provided formatting hooks.

**JSON Order**
`serde_json` is configured with `preserve_order` at the workspace level to keep field order stable across all crates.
