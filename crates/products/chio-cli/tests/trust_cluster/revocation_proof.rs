use reqwest::blocking::Client;

use super::get_json;

pub(super) fn assert_cluster_pair_same_second(
    client: &Client,
    leader_url: &str,
    service_token: &str,
) {
    let stored_revoked_at = |capability_id: &str| {
        let revocations = get_json(
            client,
            &format!("{leader_url}/v1/revocations?capabilityId={capability_id}&limit=10"),
            service_token,
        );
        revocations["revocations"]
            .as_array()
            .and_then(|records| {
                records
                    .iter()
                    .find(|record| record["capabilityId"].as_str() == Some(capability_id))
            })
            .and_then(|record| record["revokedAt"].as_i64())
            .expect("stored revocation must carry revokedAt")
    };
    let leader_revoked_at = stored_revoked_at("cap-revoke-leader");
    let follower_revoked_at = stored_revoked_at("cap-revoke-follower");
    assert_eq!(
        leader_revoked_at, follower_revoked_at,
        "qualification requires both revocations to share one unix second"
    );
    println!("same-second revocation proof: revokedAt={leader_revoked_at}");
}
