//! Trust-boundary fuzz target for `chio-openapi-mcp-bridge` spec-ingest (`OpenApiMcpBridge::from_spec`).

#![no_main]

use chio_openapi_mcp_bridge::fuzz::fuzz_openapi_ingest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_openapi_ingest(data);
});
