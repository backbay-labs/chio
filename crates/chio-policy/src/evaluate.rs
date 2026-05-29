//! HushSpec policy evaluation.
//!
//! Ported from the HushSpec reference implementation. Evaluates an action
//! against a policy and returns a decision (allow/warn/deny).

use crate::conditions::{evaluate_condition, validate_condition_keys, Condition, RuntimeContext};
use crate::models::{
    ComputerUseMode, ComputerUseRule, DefaultAction, ForbiddenPathsRule, HushSpec,
    InputInjectionRule, OriginMatch, OriginProfile, PatchIntegrityRule, PathAllowlistRule,
    PostureExtension, RemoteDesktopChannelsRule, SecretPatternsRule, ShellCommandsRule,
    TransitionTrigger,
};
use crate::regex_safety::{compile_generated_policy_regex, policy_regex_is_match};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

include!("evaluate/context.rs");
include!("evaluate/engine.rs");
include!("evaluate/matchers.rs");
include!("evaluate/outcomes.rs");
include!("evaluate/tests.rs");
