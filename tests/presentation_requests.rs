//! Signed wallet challenges use the published community key ring.
mod common;
use common::*;
use cplc::{DAY, cpsd, csgn};
use rand::{SeedableRng, rngs::StdRng};

#[tokio::test]
async fn sign_only_a_bounded_request_for_this_community() {
    let mut policy = memory().await;
    let mut rng = StdRng::seed_from_u64(723);
    let mut make = |community, deadline| {
        cpsd::PresentationRequest::for_epoch(
            &mut rng,
            cpsd::CommunityId::new(community).unwrap(),
            1,
            [cpsd::GateId::new("global-test").unwrap()],
            deadline,
            DAY,
        )
        .unwrap()
    };
    let request = make(COMMUNITY, NOW + 60);
    let signed = policy
        .sign_presentation_request(&request, NOW)
        .await
        .unwrap();
    let expected = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(COMMUNITY).unwrap(),
        policy.key_ring().unwrap().clone(),
    );
    assert_eq!(
        expected.authenticate(&signed, NOW).unwrap().to_bytes(),
        request.to_bytes()
    );
    assert!(expected.authenticate(&signed, NOW + 61).is_err());
    assert!(
        policy
            .key_ring()
            .unwrap()
            .verify(&signed, csgn::Kind::SettingsSnapshot, NOW)
            .is_err()
    );
    for rejected in [
        make("foreign", NOW + 60),
        make(COMMUNITY, NOW + 301),
        make(COMMUNITY, NOW - 1),
    ] {
        assert!(
            policy
                .sign_presentation_request(&rejected, NOW)
                .await
                .is_err()
        );
    }
    let mut tampered = signed;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(expected.authenticate(&tampered, NOW).is_err());
}
