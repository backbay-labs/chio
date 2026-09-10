# Native process identity fixture repair

The readiness helper verifies the recorded native executable and exact process
arguments. Homebrew Python 3.14 re-executes a framework application binary, so
using its initial launcher as that fixture made the test race with re-execution.
The test now starts `/bin/sleep` with fixed arguments and still requires the
wrong-command negative control to fail. No production identity check changed.

The original run had one error among 33 controls in a separate checkout that
also contained seven live-expiry controls. Its full error output is retained.
The corrected root checkout passed all 26 operator controls under both Python
3.11.4 and Homebrew Python 3.14.4. These are fixture tests, not real agent tests
or complete integration acceptance. The seven live-expiry controls remain
independently recorded with that fixture's source and evidence.

`raw-index.json` binds lossless originals and gzip members. Exact commands,
interpreter identities and results are in `raw/results.json.gz`. Public raw
members contain only test output and interpreter/command metadata; no owner
configuration, private database or credential file is included.
