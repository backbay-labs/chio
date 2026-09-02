//! Regression coverage for the read-only discovery companion connection.

use super::*;

/// Discovery reads run on the read-only companion connection, whose
/// `PRAGMA data_version` advances for every serving-owner commit. Applying
/// the writer's baseline there would read each legitimate write as an
/// external mutation and permanently poison the owner.
#[test]
fn companion_discovery_read_survives_authority_writes() {
    let fixture = fixture();
    let finding_id = hex64('a');
    publish_finding(
        &fixture.store,
        &finding_id,
        "regression/companion",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    install_status(&fixture, &finding_id, FindingStatusProofKind::NonInclusion);
    let read = || {
        fixture.store.require_verified_live_status(
            STATUS_FEED,
            &finding_id,
            STATUS_AUTHORIZATION_SHA256,
            NOW,
            NOW,
            600,
        )
    };
    read().expect("companion read after a write must serve");
    publish_finding(
        &fixture.store,
        &hex64('b'),
        "regression/companion-second",
        &hex64('c'),
        1_700_000_000,
        1_900_000_000,
    );
    read().expect("a later write must not poison the serving owner");
}
