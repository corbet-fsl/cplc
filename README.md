# cplc

**Community policy facade of cvld: rulebook, profile schema and signing.**

Part of `cmty` in cvld v0.4. Native Rust, FSL-1.1-ALv2. Development API;
never publish to a registry. See the [implemented contract](docs/CONTRACT.md).

## API

`Policy<R, S, K>` composes real `crbk::Storage`, cplc `Storage`, and
`csgn::PersistentSigner<K>` implementations. The service supplies one authorized
community scope and serializes the writer and public-key distribution.

- `create` / `open`: persist configuration and fence stale policy revisions.
- `schedule_rules`: delegate prospective revisions and sparse settings to crbk.
- `set_schema`: delegate validation and change classification to cshm.
- `may`: current rulebook verdict, with missing requirements; no member writes.
- `issue`: evaluate the configured admission action and sign only on success.
  The crbk defaults are one day for new members and thirty days for established
  members, with configurable caps shortened
  for proof expiry/age, upcoming policy activation and the signing-key policy.
- `set_communities`, `set_revocations`, `bump_epoch`: current community policy.
- `publish` / `published`: signed settings, schema, public communities and current
  revocations, with durable publication revisions and exact response recovery.
- `rotate`, `prune_keys`, `key_ring`: delegate community key management to csgn.
- `verify_snapshot`: signature, scope, kind, time, exact epoch and revision floor.

Snapshot JSON is `Snapshot<T> { community, revision, policy_epoch, content }`.
Protected COSE headers carry kind, issuer, issued time, expiry and key ID.
Credential JSON additionally binds the community pseudonym, handle, schema,
community gates, pins and authorized public device keys. There is no arbitrary
payload-signing endpoint and no caller-supplied "allowed" verdict.

The service authenticates admins and assembles `CredentialRequest` from trusted
a membership source and opaque cgts checked witnesses. It must not deserialize a member request
straight into these trusted inputs. cplc never executes gates, stores raw evidence,
keeps a credential/member activity history, or receives pin values/salts.

## Dependency survey

Checked crates.io metadata and public GitHub main APIs on 2026-09-30, including
each selected leaf's README and implemented contract:

| Candidate | Decision and reason |
|---|---|
| [crbk](https://github.com/corbet-foss/crbk/tree/fe70dc61262a80dd7681da853acfdad290f3910c) | Selected for sparse settings, action policies, missing requirements, prospective revisions and storage. No local rule evaluator or replacement revision engine. |
| [Cedar 4.13](https://github.com/cedar-policy/cedar), [Casbin 2.20](https://github.com/casbin/casbin-rs) (Apache-2.0) | Maintained authorization engines; do not replace the already implemented crbk contract. Another engine would require a policy translation and duplicate semantics. |
| [cshm](https://github.com/corbet-foss/cshm/tree/d136d2dbaceddfa0a19158d8f3a685a84abd06e7) | Selected for schema validation and change classification; it already delegates value validation to [jsonschema 0.58](https://github.com/Stranger6667/jsonschema) (MIT). No second schema engine. |
| [csgn](https://github.com/corbet-foss/csgn/tree/d7203f310c3c129c3f67ef4ef3e34ccf0ae8c93b) | Selected for persistent community signing, rotation and verification. Its maintained [coset 0.4](https://github.com/google/coset) (Apache-2.0) and [ed25519-dalek 3](https://github.com/dalek-cryptography/curve25519-dalek) (BSD-3-Clause) dependencies execute all crypto. Direct use would duplicate its security contract. |
| [crlt](https://github.com/corbet-foss/crlt/tree/6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc) | Ready on main; selected for scoped transactions, migrations and indexed query enforcement over official [libsql 0.9.30](https://github.com/tursodatabase/libsql) (MIT). No direct-client fallback needed. |
| [Serde](https://github.com/serde-rs/serde), [serde_json](https://github.com/serde-rs/json), [thiserror](https://github.com/dtolnay/thiserror) (MIT/Apache-2.0) | Selected for typed wire/persistence data and redacted errors. No own parser. |

Leaf and facade dependencies follow main, with one full revision per crate in
the shared CI lock snapshot. The cgts facade
is FSL-1.1-ALv2; the selected corbet-foss leaves use their documented open-source
licenses. CI checks the complete resolved graph for duplicate revisions.

## Storage and integration

The composition root opens the database and appends `crbk::SCHEMA`,
`csgn::SCHEMA` and `cplc::SCHEMA` to its complete numbered migration history.
Use `LibsqlStore::new(&db, community)` for cplc and
`csgn::LibsqlStore::new(db.community(community)?)` for signing metadata.
One database per community; every application table includes `community_id`.
No database credentials or signing secrets are read from the environment by
production code. `MemoryStore` is a real volatile implementation for tests.

Every store uses a clone of the same crlt database handle and pool.

Charter retains the complete signed settings and separate revocation envelopes.
Its admission adapter passes those original bytes to Guard, which verifies them
and delegates all/any/k-of-n decisions to crbk. Issuance uses the same crbk
evaluator. See the implemented contract for the downstream integration boundary.

Authenticating snapshot/key-ring distribution, current freshness floors,
notice delivery, schema grandfathering and emergency key revocation belong to
the service/consumers. The [contract](docs/CONTRACT.md) details failure recovery.

## Validation

All Cargo commands run on GitHub Actions with current stable Rust:
`cargo fmt --all --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`. CI retains its resolved dependency lock as an artifact.
No Cargo command runs on the workstation.

Tests use actual leaves, deterministic synthetic metadata, an in-memory backend
and real local libSQL files. The development gate exists only in tests: no paid
provider, external member data or production always-pass feature is included.
The optional real-Turso test skips unless **both** `TURSO_URL` and `TURSO_TOKEN`
are nonempty. Use a disposable database on an approved runner; the test applies
migrations and retains synthetic rows. Never put credentials in the repo or CI.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under the
[Functional Source License, Version 1.1, ALv2 Future License](LICENSE.md).

Schema-version publication uses the distinct `cplc.schema-versions.v1` purpose
inside a SchemaSnapshot envelope. It retains public schema definitions and cshm's
change classifications, including hidden-field changes, under the current epoch.
The existing current-schema snapshot remains available for cgrd. Archived versions
do not grant grandfathering or permit issuing against an older schema. Archives
share the existing document and entry bounds; they contain no member values.

## Dependency maintenance and coverage

First-party dependencies follow `main`; Cargo.lock records one exact revision
per crate. CI checks the entire resolved graph, including optional declarations.
Dependabot covers Cargo and GitHub Actions (there is no npm manifest here).
The merge workflow uses GitHub metadata only and requires every substantive CI
job and all published checks to succeed on the exact Dependabot head. It never
executes PR code with write permissions or bypasses branch protection.

[cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) supplies LLVM line and
branch measurements; the strict gate and exclusions are in [COVERAGE.md](docs/COVERAGE.md).

## Beacon publication

Policy owns `cbcn` Beacon's injected publisher and current cache. `trust_feed(now)`
returns an unchanged complete view while the policy revision, epoch, keys and
signed lifetime remain current; `refresh_trust(now)` explicitly republishes all
five original documents and the manifest. `trust_changes(revision, now)` returns
a whole-view hint. Durable signing and counter ownership remain here. Global
policy can implement the same LGPL Publisher port without depending on cplc.
