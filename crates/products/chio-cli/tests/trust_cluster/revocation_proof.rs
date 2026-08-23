use reqwest::blocking::Client;
use std::path::Path;
use std::time::Duration;

use chio_kernel::RevocationRecord;
use chio_store_sqlite::SqliteRevocationStore;

use super::{
    cluster_status_diagnostics, get_json, try_get_json, try_internal_cluster_status,
    wait_until_with_diagnostics,
};

fn stored_revoked_at(
    client: &Client,
    leader_url: &str,
    service_token: &str,
    capability_id: &str,
) -> i64 {
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
}

pub(super) fn insert_same_second_backfill_after_follower_cursor(
    client: &Client,
    leader_url: &str,
    follower_url: &str,
    service_token: &str,
    leader_revocation_db: &Path,
) {
    let first_revoked_at =
        stored_revoked_at(client, leader_url, service_token, "cap-revoke-leader");
    wait_until_with_diagnostics(
        "follower revocation cursor advances before same-second backfill",
        Duration::from_secs(120),
        || {
            let cursor_advanced = try_internal_cluster_status(client, follower_url, service_token)
                .and_then(|status| status["peers"].as_array().cloned())
                .and_then(|peers| {
                    peers.into_iter().find(|peer| {
                        peer["peerUrl"].as_str() == Some(leader_url)
                            && peer["revocationCursor"]["seq"].as_u64().unwrap_or(0) >= 1
                    })
                })
                .is_some();
            let first_visible = try_get_json(
                client,
                &format!("{follower_url}/v1/revocations?capabilityId=cap-revoke-leader&limit=10"),
                service_token,
            )
            .is_some_and(|value| value["revoked"].as_bool() == Some(true));
            cursor_advanced && first_visible
        },
        || {
            cluster_status_diagnostics(
                client,
                &[leader_url.to_string(), follower_url.to_string()],
                service_token,
            )
        },
    );

    SqliteRevocationStore::open(leader_revocation_db)
        .expect("open leader revocation store for controlled backfill")
        .upsert_revocation(&RevocationRecord {
            capability_id: "cap-revoke-follower".to_string(),
            revoked_at: first_revoked_at,
        })
        .expect("insert lower-sorting same-second revocation after cursor advance");
    println!("same-second revocation cursor proof: follower advanced before lexical backfill");
}

pub(super) fn assert_cluster_pair_same_second(
    client: &Client,
    leader_url: &str,
    service_token: &str,
) {
    let leader_revoked_at =
        stored_revoked_at(client, leader_url, service_token, "cap-revoke-leader");
    let follower_revoked_at =
        stored_revoked_at(client, leader_url, service_token, "cap-revoke-follower");
    assert_eq!(
        leader_revoked_at, follower_revoked_at,
        "qualification requires both revocations to share one unix second"
    );
    println!("same-second revocation proof: revokedAt={leader_revoked_at}");
}
