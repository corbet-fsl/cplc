//! Exercise actual private validation with adversarial values, without forged capabilities.
use super::*;
use serde_json::json;

fn state() -> StoredPolicy {
    serde_json::from_value(json!({
        "community":"garden", "revision":1, "epoch":1,
        "config":{"credential_action":"admit", "snapshot_validity":crate::DAY},
        "schema":{"community":"garden", "version":1,
            "public":[{"id":"ready", "label":"Ready?", "kind":{"type":"yes_no"},
                "required":true, "filterable":true, "change_preset":"stable", "no_contact_details":false}],
            "private":[]},
        "schema_versions":[], "communities":[],
        "revocations":{"members":[], "devices":[]}, "publications":{}
    }))
    .unwrap()
}
fn subject() -> crbk::Subject<'static> {
    crbk::Subject {
        id: "member",
        membership: crbk::MembershipState::Admitted,
    }
}
fn gate() -> crbk::GateResult {
    crbk::GateResult {
        gate: "verified".into(),
        provider: "provider".into(),
        level: GateLevel::Community,
        community: Some("garden".into()),
        subject: "member".into(),
        valid_until: 1000,
        proven_at: Some(100),
    }
}

#[test]
fn request_validation_refuses_independently_bad_bindings_and_bounds() {
    for case in 0..15 {
        let mut stored = state();
        let mut subject = subject();
        let mut version = 1;
        let mut gates = vec![gate()];
        let mut pins = vec![];
        let mut devices = vec![[1; 32]];
        match case {
            0 => version = 2,
            1 => subject.membership = crbk::MembershipState::Pending,
            2 => gates = vec![gate(); MAX_ENTRIES + 1],
            3 => {
                pins = vec![
                    crate::Pin {
                        field: "ready".into(),
                        fingerprint: [0; 32]
                    };
                    MAX_ENTRIES + 1
                ]
            }
            4 => devices.clear(),
            5 => devices = vec![[1; 32]; MAX_ENTRIES + 1],
            6 => gates[0].subject = "another".into(),
            7 => gates[0].community = Some("another".into()),
            8 => gates[0].level = GateLevel::Global,
            9 => gates.push(gate()),
            10 => devices.push([1; 32]),
            11 => {
                stored.schema.as_mut().unwrap().public[0].change_preset = cshm::ChangePreset::Free;
                pins.push(crate::Pin {
                    field: "ready".into(),
                    fingerprint: [0; 32],
                });
            }
            12 => {
                pins = vec![
                    crate::Pin {
                        field: "ready".into(),
                        fingerprint: [0; 32]
                    };
                    2
                ]
            }
            13 => {
                stored.revocations.members.insert("member".into());
            }
            _ => {
                stored.revocations.devices.insert([1; 32]);
            }
        }
        assert!(
            validate_request(
                &stored, &subject, "handle", version, &gates, &pins, &devices
            )
            .is_err(),
            "case {case}"
        );
    }
    let stored = state();
    let mut global = gate();
    global.level = GateLevel::Global;
    global.community = None;
    // This is only structural validation. It creates no credential or checked gate capability.
    validate_request(&stored, &subject(), "handle", 1, &[global], &[], &[[1; 32]]).unwrap();
}

#[test]
fn membership_validation_refuses_foreign_or_inconsistent_source_facts() {
    for case in 0..6 {
        let mut facts = crate::MembershipFacts {
            community: "garden".into(),
            member: "member".into(),
            state: crbk::MembershipState::Admitted,
            probation_until: Some(crate::DAY),
            lease_end: 2 * crate::DAY,
            authorized_devices: vec![[1; 32]],
        };
        match case {
            0 => facts.community = "another".into(),
            1 => facts.member = "another".into(),
            2 => facts.state = crbk::MembershipState::Lapsed,
            3 => facts.lease_end = 0,
            4 => facts.lease_end += 1,
            _ => facts.probation_until = Some(1),
        }
        assert!(validate_membership("garden", "member", &facts, 100).is_err());
    }
}

#[test]
fn deadline_queries_the_real_rulebook_at_inclusive_proof_age_boundaries() {
    for (age, expected) in [(0, 101), (1, 102), (7, 108), (899, 1000)] {
        let policy = crbk::ActionPolicy {
            all_of: vec![crbk::Requirement {
                gate: "verified".into(),
                level: GateLevel::Community,
                provider: None,
            }],
            maximum_proof_age: Some(age),
            ..Default::default()
        };
        let snapshot = crbk::Snapshot {
            community: "garden".into(),
            kind: crbk::SnapshotKind::Settings,
            revision: 1,
            policy_epoch: 1,
            issued: 100,
            content: [
                (
                    crbk::action_key("admit"),
                    serde_json::to_value(policy).unwrap(),
                ),
                (
                    crbk::gate_key(GateLevel::Community, "verified"),
                    json!(true),
                ),
                (
                    crbk::provider_key(GateLevel::Community, "verified", "provider"),
                    json!(true),
                ),
            ]
            .into(),
        };
        let evidence = [gate()];
        let decide = |now| snapshot.may(subject(), "admit", evidence.as_slice(), now);
        assert!(decide(100).unwrap().allowed);
        assert_eq!(policy_deadline(100, 1000, decide).unwrap(), expected);
        let mut disabled = snapshot;
        disabled.content.insert(
            crbk::gate_key(GateLevel::Community, "verified"),
            json!(false),
        );
        assert!(matches!(
            credential_gates(&disabled, &subject(), &evidence, 100, 1000),
            Err(Error::Invalid("unusable gate result"))
        ));
    }
}

#[test]
fn encoded_payload_bound_is_checked_before_signing() {
    assert!(matches!(
        encode(&"x".repeat(MAX_DOCUMENT_BYTES)),
        Err(Error::Invalid("payload size"))
    ));
}
