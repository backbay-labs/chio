# Chio relay catch-up ladder pin enforcement

## Objective

Make catch-up responses enforce directory-pinned ladder references for returned
frames. Catch-up must not serve stored transit material whose hops touching the
requester are not authorized by the receiver-owned peer directory.

## Plan

1. Add a failing relay service test where a receiver or hub requester asks for
   catch-up and the stored frame contains an unpinned transit ladder touching
   that requester.
2. Enforce requester ladder pins over every returned catch-up batch before
   returning a successful response.
3. Preserve existing role, treaty subscription, limit, and signed request
   behavior.
4. Run the focused relay test, broader relay service tests, clippy, formatting,
   whitespace, and dash scan.

## Verification

- [x] `cargo test -p chio-pheromone-relay relay_catchup_rejects_returned_frame_with_unpinned_transit_ladder --test relay` fails before implementation.
- [x] `cargo test -p chio-pheromone-relay relay_catchup_rejects_returned_frame_with_unpinned_transit_ladder --test relay`
- [x] `cargo test -p chio-pheromone-relay --test relay service::`
- [x] `cargo clippy -p chio-pheromone-relay --all-targets -- -D warnings`
- [x] `cargo fmt --all -- --check`
- [x] `git diff --check`
- [x] Unicode dash scan over changed files.
