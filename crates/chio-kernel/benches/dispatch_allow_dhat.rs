//! Allocation-count bench for the dispatch_allow baseline.

#[path = "fixtures/dispatch_request_fixture.rs"]
mod dispatch_request_fixture;

use dispatch_request_fixture::DispatchAllowFixture;

#[cfg(any(dhat, feature = "dhat-heap"))]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const DISPATCH_ALLOW_TOTAL_BLOCK_BUDGET: u64 = 512;
const DISPATCH_ALLOW_TOTAL_BYTE_BUDGET: u64 = 40_960;

fn dispatch_allow_probe(fixture: &DispatchAllowFixture) -> bool {
    std::hint::black_box(fixture.dispatch_allow_once())
}

#[cfg(any(dhat, feature = "dhat-heap"))]
fn main() {
    let fixture = DispatchAllowFixture::new();
    let _profiler = dhat::Profiler::builder().testing().build();

    std::hint::black_box(dispatch_allow_probe(&fixture));

    let stats = dhat::HeapStats::get();
    println!(
        "dhat allocation-count baseline: dispatch_allow total_blocks={} total_bytes={} max_blocks={} max_bytes={} curr_blocks={} curr_bytes={}",
        stats.total_blocks,
        stats.total_bytes,
        stats.max_blocks,
        stats.max_bytes,
        stats.curr_blocks,
        stats.curr_bytes
    );

    dhat::assert!(
        stats.total_blocks <= DISPATCH_ALLOW_TOTAL_BLOCK_BUDGET,
        "dispatch_allow total allocation blocks exceeded baseline budget"
    );
    dhat::assert!(
        stats.total_bytes <= DISPATCH_ALLOW_TOTAL_BYTE_BUDGET,
        "dispatch_allow total allocation bytes exceeded baseline budget"
    );
}

#[cfg(not(any(dhat, feature = "dhat-heap")))]
fn main() {
    eprintln!("dispatch_allow_dhat requires cfg(dhat) or the dhat-heap feature");
    std::process::exit(1);
}
