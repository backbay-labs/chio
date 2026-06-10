#!/usr/bin/env bash
# Thin wrapper that dispatches to the unified SDK release driver.
exec "$(dirname "$0")/check-sdk-release.sh" py "$@"
