# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Policy facade of cvld: rulebook, profile schema and signing.
- Read docs/CONTRACT.md before changing public boundaries.
- **Search before you write**: survey maintained crates first; prefer a thin facade over an established library; record candidates, choice and reasons in the README.
- No own cryptographic primitives. No login dates, no request logs, no raw gate data.
- Storage only through `crlt` (Turso/libSQL); one database per community with a community key in every table; every query index-backed.
- This crate is FSL-1.1-ALv2. Do not add dependencies available only under GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo test` must pass.
- Do not run Cargo on the workstation, including formatting or metadata. Push and let GitHub Actions run; read results with `gh run list` / `gh run view --log-failed`.
- Tests: real round trips with libSQL (local file or in-memory), no mocks of our own logic; ample edge cases.
- Commits: plain English, imperative; no AI attribution. Never publish to a registry.

- First-party Git dependencies follow branch main; resolve one full locked revision per crate.
- Dependabot merge requires protected exact-head substantive CI and full line/branch coverage.
- Stage explicit paths, pull with rebase before pushing, and never force-push.
