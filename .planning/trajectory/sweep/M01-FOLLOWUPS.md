# M01 Followups

These items are tracked from `.planning/audits/M01-error-taxonomy.md` and are not P0/P1/P2 blockers for the sweep PR.

| Source | Severity | Owner artifact | Rationale |
| --- | --- | --- | --- |
| M01 audit live-host VSCode integration test | P2 advisory | Future editor integration qualification plan | The sweep host does not provide a VSCode extension host. Existing vitest coverage pins extension wiring until a host-backed lane is available. |
| M01 audit Zed wasm bundle publication | P2 advisory | Future editor release packaging plan | `zed_extension_api` requires wasm32 packaging through `zed extension publish`; the host-side crate build remains the local verification gate. |
