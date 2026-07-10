use sigstore::bundle::Bundle;
use sigstore_protobuf_specs::dev::sigstore::bundle::v1::verification_material;

pub(super) fn leaf_der(bundle: &Bundle) -> Option<Vec<u8>> {
    let material = bundle.verification_material.as_ref()?;
    match material.content.as_ref()? {
        verification_material::Content::X509CertificateChain(chain) => chain
            .certificates
            .first()
            .map(|cert| cert.raw_bytes.clone()),
        verification_material::Content::Certificate(cert) => Some(cert.raw_bytes.clone()),
        _ => None,
    }
}

pub(super) fn rekor_metadata(bundle: &Bundle) -> Option<(u64, i64)> {
    let material = bundle.verification_material.as_ref()?;
    let entry = material.tlog_entries.first()?;
    Some((entry.log_index as u64, entry.integrated_time))
}
