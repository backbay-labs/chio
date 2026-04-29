#!/usr/bin/env bash
# Thin wrapper preserved for CI compatibility. Dispatches to the unified
# SDK release driver.
exec "$(dirname "$0")/check-sdk-release.sh" guard-cpp "$@"
