//! Trust-boundary fuzz target for `chio-config` YAML loader (`load_from_str`).

#![no_main]

use chio_config::fuzz::fuzz_chio_yaml_parse;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    fuzz_chio_yaml_parse(data);
});
