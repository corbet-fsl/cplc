#![allow(dead_code)]

use cplc::{crbk, crlt, csgn, cshm, *};
use serde_json::json;

pub const COMMUNITY: &str = "example";
pub const NOW: u64 = 100;
pub const MEMBER: &str = "community-pseudonym";
pub const DEVICE: [u8; 32] = [9; 32];
pub const DEVICES: &[[u8; 32]] = &[DEVICE];
pub type MemoryPolicy = Policy<crbk::MemoryStore, MemoryStore, csgn::MemoryStore>;
pub type SqlPolicy = Policy<crbk::LibsqlStore, LibsqlStore, csgn::LibsqlStore>;

pub fn key(seed: u8) -> csgn::SecretKey {
    csgn::SecretKey::from_seed(&mut [seed; 32])
}
pub fn config() -> Config {
    Config {
        credential_action: "admit".into(),
        snapshot_validity: DAY,
    }
}
pub fn subject() -> crbk::Subject<'static> {
    crbk::Subject {
        id: MEMBER,
        membership: crbk::MembershipState::Admitted,
    }
}
pub fn schema(version: u32) -> cshm::Schema {
    serde_json::from_value(json!({"community": COMMUNITY, "version": version,
        "public": [{"id": "weekends", "label": "Do weekends suit you?", "kind": {"type":"yes_no"}, "required": true,
        "filterable": true, "change_preset": "stable", "no_contact_details": false}], "private": []})).unwrap()
}
pub fn requirement(gate: &str, level: crbk::GateLevel) -> crbk::Requirement {
    crbk::Requirement {
        gate: gate.into(),
        level,
        provider: None,
    }
}
pub fn admission() -> crbk::ActionPolicy {
    crbk::ActionPolicy {
        all_of: vec![requirement("development", crbk::GateLevel::Community)],
        ..Default::default()
    }
}
pub fn book(policy: crbk::ActionPolicy) -> crbk::Rulebook {
    use crbk::*;
    let mut book = Rulebook::default();
    for (gate, level) in [
        ("development", GateLevel::Community),
        ("voucher", GateLevel::Community),
        ("phone", GateLevel::Global),
    ] {
        for key in [gate_key(level, gate), provider_key(level, gate, "test")] {
            book.define(
                key,
                Setting {
                    value_type: SettingType::Boolean,
                    nullable: true,
                    default: json!(true),
                    bounds: Bounds::default(),
                    lowest_layer: Layer::Community,
                    kind: SettingKind::Technical,
                },
            )
            .unwrap();
        }
    }
    book.define(
        action_key("admit"),
        Setting {
            value_type: SettingType::Policy,
            nullable: true,
            default: serde_json::to_value(policy).unwrap(),
            bounds: Bounds::default(),
            lowest_layer: Layer::Community,
            kind: SettingKind::Technical,
        },
    )
    .unwrap();
    book.define(
        "quota",
        Setting {
            value_type: SettingType::Integer,
            nullable: true,
            default: json!(10),
            bounds: Bounds {
                min: Some(0.into()),
                max: Some(100.into()),
            },
            lowest_layer: Layer::Member,
            kind: SettingKind::Template,
        },
    )
    .unwrap();
    book
}
pub fn change(rulebook: crbk::Rulebook, epoch: u64, effective_at: i64) -> crbk::Change {
    crbk::Change {
        rulebook,
        announced_at: NOW as i64,
        effective_at,
        notice_seconds: 0,
        policy_epoch: epoch,
    }
}

// A development-only test gate: synthetic verified metadata, no provider call.
// This helper is compiled only as an integration-test fixture, never the library.
pub fn development_gate(until: i64) -> crbk::GateResult {
    crbk::GateResult {
        gate: "development".into(),
        level: crbk::GateLevel::Community,
        subject: MEMBER.into(),
        community: Some(COMMUNITY.into()),
        provider: "test".into(),
        valid_until: until,
        proven_at: Some(NOW as i64),
    }
}
pub fn request(gates: &[crbk::GateResult]) -> TestRequest<'_> {
    TestRequest {
        subject: subject(),
        handle: "testmember",
        schema_version: 1,
        class: MemberClass::New,
        gates,
        pins: &[],
        devices: DEVICES,
    }
}
pub async fn memory_with(book: crbk::Rulebook) -> MemoryPolicy {
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let mut policy = Policy::create(
        crbk::MemoryStore::default(),
        MemoryStore::new(COMMUNITY).unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap();
    configure(&mut policy, book).await;
    policy
}
pub async fn memory() -> MemoryPolicy {
    memory_with(book(admission())).await
}
pub async fn configure<R: crbk::Storage, S: Storage, K: csgn::Store>(
    policy: &mut Policy<R, S, K>,
    book: crbk::Rulebook,
) {
    policy
        .schedule_rules(None, change(book, 1, NOW as i64))
        .await
        .unwrap();
    policy.set_schema(schema(1)).await.unwrap();
}
pub fn migrations() -> Vec<crlt::Migration<'static>> {
    vec![
        crlt::Migration::new(1, "rulebook", crbk::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "policy", SCHEMA),
    ]
}
pub async fn databases(url: &str, token: &str) -> (crlt::Db, crlt::Db) {
    let db = crlt::Db::open(crlt::Config::new(url, token)).await.unwrap();
    db.migrate(&migrations()).await.unwrap();
    let rules_db = db.clone();
    (db, rules_db)
}
pub async fn sql_policy(db: &crlt::Db, rules_db: &crlt::Db, community: &str) -> SqlPolicy {
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community(community).unwrap()),
        community,
        key(1),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    Policy::create(
        crbk::LibsqlStore::new(rules_db.clone()),
        LibsqlStore::new(db, community).unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap()
}
pub async fn local() -> (tempfile::TempDir, crlt::Db, crlt::Db, SqlPolicy) {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("policy.db").display());
    let (db, rules_db) = databases(&url, "").await;
    let mut policy = sql_policy(&db, &rules_db, COMMUNITY).await;
    configure(&mut policy, book(admission())).await;
    (dir, db, rules_db, policy)
}
pub fn decode_credential(ring: &csgn::KeyRing, cose: &[u8], now: u64) -> (Credential, u64) {
    let verified = ring.verify(cose, csgn::Kind::Credential, now).unwrap();
    (
        serde_json::from_slice(verified.payload()).unwrap(),
        verified.valid_until(),
    )
}
pub fn expectation(kind: SnapshotKind, epoch: u64, now: u64) -> SnapshotExpectation<'static> {
    SnapshotExpectation {
        community: COMMUNITY,
        kind,
        minimum_revision: 1,
        policy_epoch: epoch,
        now,
    }
}

// Raw external provider fixtures remain confined to tests. Production accepts only
// cgts witnesses. Real rulebook, legal, gate storage and signing code execute below.
#[derive(Clone, Copy)]
pub enum MemberClass {
    New,
    Established,
}
pub struct TestRequest<'a> {
    pub subject: crbk::Subject<'a>,
    pub handle: &'a str,
    pub schema_version: u32,
    pub class: MemberClass,
    pub gates: &'a [crbk::GateResult],
    pub pins: &'a [Pin],
    pub devices: &'a [[u8; 32]],
}

#[derive(Clone)]
pub struct NoAuthority;
impl clbs::Verifier for NoAuthority {
    async fn verify_legal(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
    async fn verify_self_ban(&self, _: &clbs::SignedOrder) -> clbs::Result<()> {
        Err(clbs::Error::Denied)
    }
}
struct FixtureGate(crbk::GateResult);
impl cgts::Gate for FixtureGate {
    type Input = ();
    fn descriptor(&self) -> cgts::Descriptor {
        cgts::Descriptor {
            gate: self.0.gate.clone(),
            provider: self.0.provider.clone(),
            level: self.0.level,
            steps: vec![cgts::Step {
                id: "submit".into(),
                description: "Test provider evidence".into(),
                input: "unit".into(),
            }],
        }
    }
    async fn verify(&self, context: cgts::Context<'_>, _: &()) -> cgts::Result<cgts::Proof> {
        if self.0.subject != context.subject
            || self.0.community.as_deref() != Some(&context.snapshot.community)
            || self.0.proven_at.is_some_and(|time| time > context.now)
        {
            return Err(cgts::Error::Scope);
        }
        Ok(cgts::Proof::transient(self.0.valid_until))
    }
}
pub struct FixtureMembership {
    pub member: String,
    pub state: crbk::MembershipState,
    pub probation_until: Option<u64>,
    pub lease_end: u64,
    pub authorized_devices: Vec<[u8; 32]>,
}
impl MembershipSource for FixtureMembership {
    type Lease = ();
    async fn membership(&self, member: &str, _: u64) -> Result<(MembershipFacts, Self::Lease)> {
        if self.member != member {
            return Err(Error::Invalid("fixture member"));
        }
        Ok((
            MembershipFacts {
                community: COMMUNITY.into(),
                member: self.member.clone(),
                state: self.state,
                probation_until: self.probation_until,
                lease_end: self.lease_end,
                authorized_devices: self.authorized_devices.clone(),
            },
            (),
        ))
    }
}
pub async fn checked(
    snapshot: &VerifiedSnapshot,
    subject: &str,
    action: &str,
    gates: &[crbk::GateResult],
    now: u64,
) -> Result<cgts::CheckedGates> {
    let keeper = cgts::Gatekeeper::new(
        cgts::MemoryStore::new(COMMUNITY).unwrap(),
        cgts::LegalGate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), NoAuthority),
    )
    .unwrap();
    let context = cgts::Context {
        snapshot: snapshot.settings(),
        subject,
        action,
        now: now as i64,
    };
    let mut checks = Vec::new();
    for gate in gates {
        if gate.valid_until <= now as i64 {
            continue;
        }
        match keeper.run(context, &FixtureGate(gate.clone()), &()).await {
            Ok(check) => checks.push(check),
            Err(cgts::Error::Disabled) => {}
            Err(_) => return Err(Error::Invalid("test evidence refused")),
        }
    }
    keeper
        .check(context, checks)
        .await
        .map_err(|_| Error::Invalid("test evidence refused"))
}

pub trait TestPolicyApi {
    async fn issue_test(&mut self, request: TestRequest<'_>, now: u64) -> Result<Vec<u8>>;
    async fn may_test(
        &mut self,
        subject: crbk::Subject<'_>,
        action: &str,
        gates: &[crbk::GateResult],
        now: u64,
    ) -> Result<crbk::Decision>;
}
impl<R: crbk::Storage, S: Storage, K: csgn::Store> TestPolicyApi for Policy<R, S, K> {
    async fn issue_test(&mut self, request: TestRequest<'_>, now: u64) -> Result<Vec<u8>> {
        let snapshot = self.verified_settings(now).await?;
        let gates = checked(&snapshot, request.subject.id, "admit", request.gates, now).await?;
        let source = FixtureMembership {
            member: request.subject.id.into(),
            state: request.subject.membership,
            probation_until: match request.class {
                MemberClass::New => Some(14 * DAY),
                MemberClass::Established => None,
            },
            lease_end: 90 * DAY,
            authorized_devices: DEVICES.to_vec(),
        };
        self.issue(
            &source,
            CredentialRequest {
                subject: request.subject,
                handle: request.handle,
                schema_version: request.schema_version,
                snapshot: &snapshot,
                gates: &gates,
                pins: request.pins,
                devices: request.devices,
            },
            now,
        )
        .await
    }
    async fn may_test(
        &mut self,
        subject: crbk::Subject<'_>,
        action: &str,
        gates: &[crbk::GateResult],
        now: u64,
    ) -> Result<crbk::Decision> {
        let snapshot = self.verified_settings(now).await?;
        let gates = checked(&snapshot, subject.id, action, gates, now).await?;
        self.may(&snapshot, subject, action, &gates, now).await
    }
}
