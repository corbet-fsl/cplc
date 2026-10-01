# cplc implemented contract

## Binding scope

Policy facade over `crbk` (rulebook), `cshm` (profile schema) and `csgn`
(community signing keys), under `cmty` in cvld v0.4. Policy reaches the global
service only as signed snapshots. Global issuance, keys, suspension and databases
remain separate. Rust on current stable; FSL-1.1-ALv2; no registry publication.
No own cryptographic primitives. No login dates, request logs or raw gate data.
Use maintained leaves on main with one exact locked revision each. Storage goes through `crlt`, with one
database per community, a community key in every table and indexed queries.
Tests exercise real leaf operations and real local libSQL on GitHub Actions.

## Composition and trust boundary

`Policy<R, S, K>` owns a crbk storage implementation, a cplc storage implementation
and a csgn `PersistentSigner<K>`. Run one writer per community. Serialize all
configuration changes, issuance, rotation and public-ring delivery through that
writer. All mutating facade methods require exclusive access. Revision fencing
is defense against stale writers, not a distributed publication protocol.

The composition root supplies authenticated community routing, trusted Unix
seconds, administrator authorization, cgts checked witnesses and a cmbr membership source,
a canonical reserved handle, authorized pins and public device keys. None of
these Rust inputs is evidence of remote authentication. In particular, exposing
`CredentialRequest` directly as a member-facing signing endpoint is unsafe.
The admission action is persisted in configuration and cannot be selected by an
issuance request. The facade evaluates that action itself using crbk; it never
accepts a caller-provided verdict.

The signer issuer must exactly equal the community identifier. Global issuers
must use another scope and separate keys. Seeds are provisioned in the service's
secret store, never Turso. csgn alone performs signing, key rotation, key retention,
canonical COSE verification and durable signing-state updates.

## Configuration and epochs

crbk owns sparse resolution, immutable revisions, template/catalogue rules,
prospective activation and minimum notice. `schedule_rules` delegates its write
and validation to that leaf. Each rulebook revision must advance its policy epoch by exactly one, beginning
at one. An administrator cannot jump to an epoch that exhausts later revocations. Only `Selection::At(now)` is used for decisions; future revisions never activate
early. The effective epoch is the checked sum of the facade counter and the active
rulebook epoch. Both components only increase. Immediate edits advance the facade
counter; each scheduled revision advances the other component when it activates.
Thus an immediate revocation cannot mask a later scheduled epoch transition.
Overflow fails closed; epochs fit positive signed 64-bit integers.

cshm owns schema validation and change classification. The facade persists one
current schema and requires increasing versions. Schema edits, public community
list edits, revocations and explicit epoch bumps are immediate administrative
operations and invalidate older epochs. The caller must review classification
before authorizing an edit; migration/grandfathering and notice delivery are
upstream responsibilities. The public community list is explicit input, never
inferred from member activity or cross-community joins.

## Signed publications and credentials

Four kinds are published: settings (flat `crbk::Values`), schema (`cshm::Schema`),
communities (ordered public identifier set), and revocation list (`Revocations`).
JSON `Snapshot<T>` contains community, positive publication revision, policy epoch
and content. Protected COSE headers carry kind, issued time, exclusive expiry,
issuer and key ID. These authenticated fields are not duplicated in JSON.
Publication revisions are independent per kind and increase even on refresh.
Only the latest signed bytes of each kind are retained; policy edits clear cached
bytes while preserving revision counters. Snapshot lifetime is bounded by config,
csgn's maximum and the next scheduled rulebook activation.

Credentials carry community, member pseudonym, canonical handle, community gates
with expiries, pin fingerprints, authorized device keys, schema version and epoch.
The enclosing COSE supplies issuance, expiry and key ID. Global proof metadata
participates in the decision but is never copied into the credential or storage.
Credential issuance stores no credential, pseudonym, proof or login history.
Current revocations are explicit policy state, not an activity log.

The membership source is selected by the service composition root, and reads
current state, probation and lease from cmbr. Callers cannot select a lifetime
class. cplc rejects Pending, Lapsed and Released even if a request claims Admitted.
The resolved crbk settings `membership.new_credential_days`,
`membership.established_credential_days` and `membership.probation_days` default
to 1, 30 and 14. Probation is a stored exclusive UTC-day boundary; absent or
passed probation selects established validity. Both credential caps are at most
30 days and may be shortened by policy. Credentials never outlive the lease.
They are also shortened to csgn's lifetime limit, proof expiry and the next
announced policy activation. Maximum-proof-age expiry is determined by asking
crbk at future times within this fixed policy interval, not by another policy
engine. Every included gate covers the entire signed lifetime. Subject/scope
mismatches, duplicate community gates, revoked members/devices, invalid pins,
missing schema, wrong schema version and any membership other than Admitted fail closed, even
when the action has no membership requirement. Credential Debug output is redacted.
Community signer namespaces contain only ASCII letters, digits, dot, dash and
underscore; the global cglb: namespace is reserved.

## Durability

The cplc storage trait atomically loads/replaces one community document with a
revision comparison. Both memory and crlt/libSQL implementations enforce the same
state validation and counter/epoch monotonicity. The libSQL row uses primary key
`(community_id, slot)` and stores current schema, config, public communities,
aggregate epochs and publication counters/latest policy COSE. Revocations live
in separate indexed rows.
No signing secret or member credential is stored. Application read/write query
plans are checked by crlt and by adapter tests. The service owns migration numbers
and supplies complete migration history for cplc, crbk and csgn.

Publication ordering is sign and persist csgn retention, then persist publication,
then return bytes. Failed publication never returns a signature. An uncertain or
cancelled cplc mutation disables that facade until reopening. csgn applies its
own fail-closed rule to signing-state mutations. These stores are not one SQL
transaction: an orphaned signing retention update is safe over-retention, not a
published credential. Rulebook writes have their own atomic leaf transaction;
uncertain outcomes require reconciliation, never automatic retry.

## Verification and limits

`verify_snapshot` uses an authenticated csgn ring, expected scope/kind, exact
expected epoch and a caller-held revision floor. Signature authenticity does not
make an old epoch current; callers must obtain fresh authenticated floors and
revocations. Consumers validate typed content semantics (cshm for schema, crbk
for settings). cplc is not a replacement for cgrd's profile/bundle checks.

Facade documents are limited to 1 MiB; public sets, fields and credential
collections to 256 entries; identifiers to 256 bytes. Services must bound
transport allocation before parsing. Errors omit SQL, credentials and input
values. Do not enable dependency SQL/HTTP debug tracing for member traffic.

## Integration limits

crbk, csgn and cplc use one revision of crlt and clones of one database handle.
CI rejects duplicate Corbet crate identities and revision/tag selectors, including
transitive ones. First-party declarations follow main; every tested graph retains
one exact locked revision per crate.

cchr retains the original complete settings and separate revocation signatures.
Its borrowed admission adapter passes those bytes to cgrd, which verifies them
and delegates all/any/k-of-n semantics to crbk. Actual door-authorized bundles
exercise this path natively and on wasm in Charter and Assurance CI. No lossy
translation or silent empty-gate fallback is provided. Production forum wiring
remains downstream. Emergency signing-key revocation and rollback-proof
recovery remain csgn/service boundaries. The development test gate is test-only;
there are no provider calls or production test-gate features.

## Door integration

`edit_setting` changes one community deviation or root platform value through
crbk, preserving all other sparse layers and advancing the policy epoch.
The service authorizes the requested layer and supplies notice timing.
`revocations` exposes current policy state to coordinated service writers.

`trust_manifest` signs a typed `TrustManifest` with a fixed `cplc.trust.v1`
purpose, community, durable policy revision, effective epoch, current schema
version and canonical public key ring. Its COSE kind is SettingsSnapshot, but
its distinct strict top-level shape prevents decoding as a flat settings
snapshot. It is an aggregate trust publication, never a member query. Signatures
use csgn's durable retention path. Consumers still need an authenticated initial
key ring and freshness floors; a self-signed ring is not a bootstrap trust root.

## Verified settings and revocation storage

`verified_settings` and `verify_settings` return an opaque `VerifiedSnapshot`.
Its immutable crbk view retains the authenticated issuance time and effective
epoch; its exclusive expiry stays attached to the witness. `validate_snapshot`
requires the current publication revision, content, epoch and validity. A raw
snapshot cannot be converted into this type; a compile-fail doctest enforces it.

Revocations use indexed `cplc_revocation` rows, committed atomically with the
policy epoch. Reads page over the primary key in batches of 256; that batch size
is not a revocation capacity limit. Memory storage enforces the same unbounded
set semantics. Published documents retain their transport size bound. A large
revocation set cannot prevent committing further revocations or advancing epochs.

`Policy::settings(now)` returns the active flattened crbk snapshot without
publishing, advancing the epoch, or recording that a caller read it. The door
uses it for checks such as reserved-handle validation, independently of the
fresh global passport proof needed for admission.

## Admission and time precision

`Policy::may` is the sole admission decision owner, delegating to crbk over the
current `VerifiedSnapshot` and cgts `CheckedGates`. `Policy::issue` requires the
same capabilities plus current facts from the authoritative membership source.
Raw snapshots and raw gate arrays cannot enter either API. Changing publication,
revision, effective epoch, action, subject or check time invalidates old receipts.
The mandatory clbs veto is included in cgts's opaque collection even if it is
empty. cmty only wires these parts; it does not assemble another decision.

Signing, key activation/rotation and ordinary credential/publication expiry use
UTC-day buckets. Provision and reopen the persistent signer with `day(now)`;
cplc refuses a key activated off the day boundary. Snapshot validity must be a
positive whole number of days. An authenticated snapshot must be live at issuance;
its distribution/cache deadline does not shorten an otherwise authorized member
credential. Scheduled policy activation does shorten credentials and publications.

Two protocol deadlines may require finer expiry precision: an authenticated
short-lived gate challenge (for example the transient profile check) and a
prospective policy activation with its exact minimum notice interval. cplc must
preserve those earlier exclusive deadlines rather than round them upward. Their
precision is never used for a stored login/proof time. COSE issuance remains the
day start even in these cases. Member probation and leases have no such exception.

Device public keys must be generated independently per community by the wallet
and authenticated/authorized by the service’s community device protocol before
issuance. cmbr owns current passkey-to-community-device bindings.
`MembershipFacts.authorized_devices` carries those current public keys under the
returned member lease, held through durable signing. Requested keys must be a
subset of that independently read set; empty or removed authority refuses
issuance. Request bytes never register or authorize a key. A reusable global
wallet key would link communities and is outside this contract. cplc also rejects
duplicates/revoked devices and cannot determine whether a public key was reused
in another isolated community database.

The global policy format consumed by cglb is signed by the separate authenticated
global policy authority described in cglb's contract. A community signer never
signs global policy or claims global issuance authority. Every credential renewal
requiring global gates needs a fresh cpsd presentation verified against the
current authenticated global epoch; a suspension prevents its next renewal.

`Policy::sign_presentation_request` signs only a typed cpsd presentation request
for the policy's own community, with a deadline at most 300 seconds ahead.
The community facade supplies its server-held challenge. The wallet authenticates
the COSE bytes using cpsd's `AuthenticatedCommunity` and the key ring discovered
for the initiating origin. This is not an arbitrary-payload signing API. The
binary cpsd purpose/version prevents confusion with a JSON membership credential.

The membership source returns a per-member lease guard with its current facts.
cplc retains this guard through signing, so revocation and membership changes
cannot race the issuance check. The guard is released on success, error or
cancellation. It is not acquired by pure lobby reads.

Current-witness validation also requires the exact signed publication bytes
stored by this policy owner. A document signed under a caller-selected foreign
ring cannot copy current values/revision and extend the authenticated lifetime.

The pure `settings` view carries the same effective epoch and day-rounded issued
time as verified publications, including local revocation bumps; reading it
does not publish or advance state.

Schema-version publication uses the distinct `cplc.schema-versions.v1` purpose
inside a SchemaSnapshot envelope. It retains public schema definitions and cshm's
change classifications, including hidden-field changes, under the current epoch.
The existing current-schema snapshot remains available for cgrd. Archived versions
do not grant grandfathering or permit issuing against an older schema. Archives
share the existing document and entry bounds; they contain no member values.

Schema changes validate the serialized schema and history publications before
commit. The core policy document and each of the five signed publications have
independent bounded size budgets: JSON byte-array expansion cannot consume the
space needed for durable policy or the other publications. Rejected history
updates leave the schema and epoch unchanged; revocation and refresh still work.

## Beacon

`refresh_trust(now)` delegates the original cvld publication sequence to `cbcn`,
then atomically installs the complete authenticated view in its current cache.
The existing persisted per-kind counters and mutation cancellation fences remain
in Policy. Failed intermediate publications may consume counters but expose no
partial feed. `trust_feed` first checks the persisted writer fence and active
policy epoch; changes or expiry refresh, ordinary reads preserve the same bytes.
No member activity, private key or SQL moves into Beacon. The door owns transport
and waiting; global publishing reuses Beacon by reference through its Publisher.

## Durable publishing-key continuity

Rotation and pruning use csgn's atomic original-proof methods and separate public
ring-change sequence. Policy copies the pending original proof into its own CAS
before acknowledging it. Reopen reconciles a pending proof, including a Policy
commit whose reply was lost or a lost signer acknowledgement. Publication and
issuance refuse while the signer ring and retained proof floor disagree.
Ordinary credential signing does not affect the public sequence, and rotation
preserves the existing policy epoch and valid old credentials. Proof lifetime
uses the signer's maximum validity; predecessor keys remain available for that
signed lifetime, including when no member credential requires them.

Beacon carries the retained bytes unchanged. History is monotonic and bounded by
256 changes and 1 MiB of original proofs. Exhaustion refuses; no transition is
silently dropped. A proof that exceeds the remaining byte budget remains durable
and pending in csgn, and the writer refuses publication until operator recovery.
That exceptional history-budget condition needs deployment reprovisioning; the
facade does not invent a root reset. No private key enters Policy storage.
