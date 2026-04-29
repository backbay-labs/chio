//! Trust-boundary fuzz target for `chio-acp-edge` NDJSON decode and `handle_jsonrpc` dispatch.

#![no_main]

use chio_acp_edge::fuzz::fuzz_acp_envelope_decode;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_acp_envelope_decode(data);
});
