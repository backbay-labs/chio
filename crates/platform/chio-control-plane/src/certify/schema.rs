pub(crate) const CERTIFICATION_SCHEMA: &str = "chio.certify.check.v1";
pub(crate) const CERTIFICATION_REGISTRY_VERSION: &str = "chio.certify.registry.v1";
pub(crate) const CRITERIA_PROFILE_ALL_PASS_V1: &str = "conformance-all-pass-v1";
pub(crate) const EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1: &str =
    "conformance-report-bundle-v1";
pub(crate) const CERTIFICATION_PUBLIC_METADATA_SCHEMA: &str = "chio.certify.discovery-metadata.v1";
pub(crate) const CERTIFICATION_PUBLIC_SEARCH_SCHEMA: &str = "chio.certify.search.v1";
pub(crate) const CERTIFICATION_PUBLIC_TRANSPARENCY_SCHEMA: &str = "chio.certify.transparency.v1";
pub(crate) const CERTIFICATION_CONSUMPTION_POLICY_PROFILE_V1: &str = "chio.certify.consume.v1";
pub(crate) const CERTIFICATION_PROVENANCE_MODE_ARTIFACT_SIGNER: &str = "artifact-signer-key";
pub(crate) const GENERATED_REPORT_MEDIA_TYPE_MARKDOWN: &str = "text/markdown";

pub(crate) fn is_supported_certification_schema(schema: &str) -> bool {
    schema == CERTIFICATION_SCHEMA
}

pub(crate) fn is_supported_certification_registry_version(version: &str) -> bool {
    version == CERTIFICATION_REGISTRY_VERSION
}

pub(crate) fn is_supported_evidence_profile(profile: &str) -> bool {
    profile == EVIDENCE_PROFILE_CONFORMANCE_REPORT_BUNDLE_V1
}
