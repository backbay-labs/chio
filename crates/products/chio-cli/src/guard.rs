mod build;
mod formatting;
mod new;
mod publish;
mod verify;

pub(crate) use build::{cmd_guard_build, cmd_guard_install, cmd_guard_pack};
pub(crate) use new::cmd_guard_new;
pub(crate) use publish::{
    cmd_guard_publish, cmd_guard_pull, GuardPublishCommand, GuardPullCommand,
};
pub(crate) use verify::{cmd_guard_bench, cmd_guard_inspect, cmd_guard_test};

use crate::CliError;

fn guard_io_error(message: impl Into<String>) -> CliError {
    CliError::cli_io_error(message)
}

fn guard_yaml_error(message: impl Into<String>) -> CliError {
    CliError::cli_yaml_error(message)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
