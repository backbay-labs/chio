pub fn truncated_leaf_der() -> &'static [u8] {
    b"\x30\x03\x02\x01\x00"
}

pub fn wrong_ca_root_pem() -> &'static [u8] {
    include_bytes!("../../fixtures/nitro/aws-nitro-root.pem")
}
