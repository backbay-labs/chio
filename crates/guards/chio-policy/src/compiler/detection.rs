use std::fs;
use std::path::{Path, PathBuf};

use super::{CompileError, PipelineBuilder};
use crate::models::{
    DetectionLevel, HushSpec, JailbreakDetection, PromptInjectionDetection, ThreatIntelDetection,
};

use chio_guards::{
    jailbreak::{DetectorConfig as JailbreakDetectorConfig, JailbreakGuardConfig},
    prompt_injection::PromptInjectionConfig,
    EmbeddingAnomalyConfig, EmbeddingAnomalyGuard, EmbeddingAnomalyPatternDb, JailbreakGuard,
    PromptInjectionGuard,
};

// ---------------------------------------------------------------------------
// Detection-extension guards (8, 9, 10)
// ---------------------------------------------------------------------------

pub(super) fn compile_detection_guards(
    policy: &HushSpec,
    builder: &mut PipelineBuilder,
    source_dir: Option<&Path>,
) -> Result<(), CompileError> {
    let Some(extensions) = &policy.extensions else {
        return Ok(());
    };
    let Some(detection) = &extensions.detection else {
        return Ok(());
    };

    // 8. detection.prompt_injection -> PromptInjectionGuard
    if let Some(pi) = &detection.prompt_injection {
        if pi.enabled.unwrap_or(true) {
            builder.add(PromptInjectionGuard::with_config(
                prompt_injection_config_from(pi),
            ));
        }
    }

    // 9. detection.jailbreak -> JailbreakGuard
    if let Some(jb) = &detection.jailbreak {
        if jb.enabled.unwrap_or(true) {
            builder.add(JailbreakGuard::with_config(jailbreak_config_from(jb)?));
        }
    }

    // 10. detection.threat_intel -> EmbeddingAnomalyGuard
    if let Some(threat_intel) = &detection.threat_intel {
        if threat_intel.enabled.unwrap_or(true) {
            builder.add(threat_intel_guard_from(threat_intel, source_dir)?);
        }
    }

    Ok(())
}

fn prompt_injection_config_from(pi: &PromptInjectionDetection) -> PromptInjectionConfig {
    let mut config = PromptInjectionConfig::default();
    if let Some(block_at) = pi.block_at_or_above {
        config.score_threshold = prompt_level_to_score_threshold(block_at);
    }
    if let Some(max_scan_bytes) = pi.max_scan_bytes {
        // Clamp to at least one byte so the guard is well-formed; zero would
        // short-circuit the scanner to a no-op and silently allow everything.
        config.max_scan_bytes = max_scan_bytes.max(1);
    }
    config
}

/// Convert a HushSpec `DetectionLevel` into a PromptInjectionGuard score
/// threshold in `[0.0, 1.0]`. Higher levels require stronger signals before
/// the guard denies.
pub(super) fn prompt_level_to_score_threshold(level: DetectionLevel) -> f32 {
    match level {
        DetectionLevel::Safe => 0.1,
        DetectionLevel::Suspicious => 0.4,
        DetectionLevel::High => 0.8,
        DetectionLevel::Critical => 1.0,
    }
}

pub(super) fn jailbreak_config_from(
    jb: &JailbreakDetection,
) -> Result<JailbreakGuardConfig, CompileError> {
    let mut config = JailbreakGuardConfig::default();
    let mut detector = JailbreakDetectorConfig::default();

    if let Some(block) = jb.block_threshold {
        // HushSpec expresses thresholds as integer percentages (0-100 in
        // practice). Map that onto the `[0.0, 1.0]` jailbreak-guard space,
        // capping at 1.0 so out-of-range values fail closed rather than
        // produce an unreachable threshold.
        let capped = u32::try_from(block).unwrap_or(0).min(100);
        config.threshold = (capped as f32) / 100.0;
    }

    // `warn_threshold` has no dedicated field on Chio's `JailbreakGuardConfig`;
    // the guard emits advisory signals based on detector-level statistical
    // thresholds. We accept the HushSpec value for schema compatibility but
    // do not wire it in here -- if the warn value would exceed the configured
    // block threshold we conservatively ignore it rather than fail closed,
    // clamping partial overlays on merge.
    let _ = jb.warn_threshold;

    if let Some(max_bytes) = jb.max_input_bytes {
        detector.max_scan_bytes = max_bytes;
    }

    config.detector = detector;
    Ok(config)
}

fn threat_intel_guard_from(
    threat_intel: &ThreatIntelDetection,
    source_dir: Option<&Path>,
) -> Result<EmbeddingAnomalyGuard, CompileError> {
    let pattern_db_path = threat_intel.pattern_db.as_deref().ok_or_else(|| {
        CompileError::Invalid(
            "detection.threat_intel.pattern_db is required when enabled".to_string(),
        )
    })?;

    let resolved_pattern_db_path = resolve_policy_asset_path(pattern_db_path, source_dir);

    let pattern_db_json = fs::read_to_string(&resolved_pattern_db_path).map_err(|error| {
        CompileError::Invalid(format!(
            "failed to read detection.threat_intel.pattern_db '{pattern_db_path}' (resolved to '{}'): {error}",
            resolved_pattern_db_path.display()
        ))
    })?;
    let pattern_db = EmbeddingAnomalyPatternDb::from_json(&pattern_db_json).map_err(|error| {
        CompileError::Invalid(format!(
            "invalid detection.threat_intel.pattern_db '{pattern_db_path}' (resolved to '{}'): {error}",
            resolved_pattern_db_path.display()
        ))
    })?;

    let mut config = EmbeddingAnomalyConfig::default();
    if let Some(similarity_threshold) = threat_intel.similarity_threshold {
        config.similarity_threshold = similarity_threshold;
    }
    if let Some(top_k) = threat_intel.top_k {
        config.top_k = top_k;
    }

    EmbeddingAnomalyGuard::new(pattern_db, config).map_err(|error| {
        CompileError::Invalid(format!(
            "invalid detection.threat_intel configuration: {error}"
        ))
    })
}

fn resolve_policy_asset_path(path: &str, source_dir: Option<&Path>) -> PathBuf {
    let candidate = PathBuf::from(path);
    if candidate.is_absolute() {
        return candidate;
    }

    match source_dir {
        Some(dir) => dir.join(candidate),
        None => candidate,
    }
}
