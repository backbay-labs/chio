# Interrupted older release qualifier

Run 34437467881, job 102745434060, attempt 1 ran source
`8408ae9996d5f011849406b07490e5ec67928e8d`. GitHub records the run and job as
failed and the Release qualification step as cancelled. The exact job log
reports a runner shutdown signal followed by operation cancellation. This
agent did not cancel or supersede the run.

The last active proof was `public_sign_receipt_accepts_matching_kernel_key`.
Its solver had started but the log contains no completed result for that
harness. Earlier proof summaries and preceding successful setup steps cannot
establish the interrupted proof or the complete release qualifier. The cause
of the runner shutdown is unknown; this record does not infer a resource
exhaustion event or a source-code defect from the interruption alone.

The full raw log, job metadata, terminal run summary and a separate newer-source
CI snapshot are retained losslessly in [manifest.json](manifest.json). The newer
source `0599e9fa3ee337719986f6fd88466f75ba0290dd` had 71 successful, 15 running
and 10 skipped source checks at that observation, with zero failed checks.
Those results neither transfer to the older source nor complete its qualifier.
Fresh exact-source hosted qualification remains required before release.

Confidence: high in the source/run identities and observed interruption;
unknown in its external cause and the interrupted harness outcome.
