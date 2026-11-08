# cplc agent instructions

Write all code comments and documentation in English. Owned code forbids unsafe
Rust (`#![forbid(unsafe_code)]`, `src/lib.rs:4`).

## Build and test (lane: `~/agents/scratch/cbuild <lane> ...`)

- `fmt -p cplc -- --check`
- `test -p cplc --no-fail-fast`
  (22 targets green + turso 1 ignored without `TURSO_URL`/`TURSO_TOKEN` + doc 2,
  exit 0; `--locked` needs CI's resolve refresh)
- `clippy -p cplc --all-targets -- -D warnings`
  (lane: blocked by pre-existing upstream `cblc` `too_many_arguments` at
  `cblc/src/accounting_ledger/extensions.rs:140`, red-at-HEAD, outside this repo;
  cplc's own code is warning-free)
- No wasm target: `check -p cplc --target wasm32-unknown-unknown` fails inside
  `mio` (unsupported); CI (`.ci/verify.sh`) does not run it either.
- CI-only (Crow): `provider-controls.py` / `test-provider-controls.py`,
  nightly `llvm-cov` strict gate (`docs/COVERAGE.md`)

## Hard invariants (each with its enforcing test in `tests/it/`)

- Read `docs/CONTRACT.md` before changing public boundaries.
- `CredentialRequest` is never a member-facing endpoint; `may`/`issue` evaluate
  the configured action themselves and never accept a caller verdict
  (`docs/CONTRACT.md:24-29`): `tests/it/policy.rs::signed_action_attests_the_real_configured_decision`,
  `tests/it/credential_format.rs::signed_format_never_defaults_an_absent_version_or_action`.
- Credentials bind the exact issuance action and cover their whole lifetime;
  revoked/expired/foreign state fails closed (`docs/CONTRACT.md:74-86,101-115`):
  `tests/it/admission_v3.rs::*`, `tests/it/current_admission.rs::*`, `tests/it/membership_facts.rs::*`.
- Epochs only increase; revocation never masks a later scheduled transition
  (`docs/CONTRACT.md:46-52`): `tests/it/configuration.rs::*`, `tests/it/key_continuity.rs::*`.
- Failed publication never returns a signature; uncertain writes disable the
  facade until reopen, never auto-retry (`docs/CONTRACT.md:133-135`):
  `tests/it/beacon.rs::*`, `tests/it/database.rs::real_database_failure_after_signing_returns_no_publication`,
  `tests/it/storage_boundaries.rs::*`.
- Signing secrets, credentials and member history are never stored; Debug output
  is redacted (`docs/CONTRACT.md:86,125-126,148`):
  `tests/it/database.rs::issuance_keeps_no_member_credential_or_activity_record`.
- FSL-1.1-ALv2; no GPL/AGPL-only dependencies (`LICENSE.md`, `deny.toml`).

Pointers: `docs/CONTRACT.md`, `docs/COVERAGE.md`.
