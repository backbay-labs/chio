pub fn not_yet_valid_leaf_pem() -> &'static [u8] {
    b"-----BEGIN CERTIFICATE-----\n\
      MIIBnotYetValidSyntheticFixture\n\
      -----END CERTIFICATE-----\n"
}

pub fn expired_leaf_der() -> &'static [u8] {
    // DER SEQUENCE prefix plus an incomplete body. This fixture is
    // deliberately malformed so the verifier fails closed before it can
    // reach signature acceptance on an expired or not-yet-valid leaf.
    b"\x30\x0a\x17\x0d700101000000Z"
}
