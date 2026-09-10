# JavaScript dependency release qualification

The hosted CVE monitor failed on five advisory identifiers across 20 lockfile occurrences. The same findings occur on the unchanged base branch. This repair selects sharp 0.35.4, js-yaml 4.3.2, Next 15.5.24, and Vitest/mocker 4.1.11, retaining Vite 7.3.6 and React 19.2.7. Private workspace test peers keep npm resolution on those compatible versions. No advisory exception or scanner rule was added or relaxed.

## Executed results

- The existing OSV command and configuration pass against a clean export of all scanned source paths, without installed dependency directories: exit 0. Existing exceptions remain visible in the raw log; zero new exceptions were added. An earlier scan including installed Expo Maven metadata produced extraction errors, which remain retained and are not counted as a pass.
- Five affected wrapper build/lint/test suites and the Next wrapper passed. Conformance initially failed nine of 73 tests. The same nine failures reproduce using the original Vitest 3 layout, establishing stale fixtures rather than a Vitest 4 regression.
- Conformance fixtures now use the current content-addressed receipt shape, required fields, real fixture signatures and an explicit verification endpoint. The verdict-matrix count reflects its existing 72 cases. Runtime validators and the test matrix are unchanged. All 73 conformance tests and lint pass with pinned Node 22.19.0. These are synthetic sidecar fixtures, not real-kernel evidence.
- Direct Sharp resizing and Miniflare's actual local image binding both successfully resize a generated image with the overridden Sharp 0.35.4 under Node 22.19.0.
- The complete repaired TypeScript release driver passes with Node 22.19.0 and Bun 1.3.3. It qualifies all 16 publishable packages, including builds, applicable suites, packing, and clean consumer import/CLI checks. Its raw output contains no skipped-test summary. This is a macOS arm64 run, not the separate hosted Linux release lane.

The pinned Node archive SHA256 is `1c3a9e78da501bbc1f0c99fbbb69bb7c722bc7a9bf30128b21ea502f3905892a`; Bun archive SHA256 is `f50f5cc767c3882c46675fbe07e0b7b1df71a73ce544aadb537ad9261af00bb1`. Their versions were checked after extraction. Earlier wrapper runs used the worker's local tools; the final full driver uses these explicit pins.

The receipt fixture repair adds no production API change. Frozen six-host candidate archives, selected kernel binary, and host acceptance counts are unchanged. New source CI and public release qualification remain required. Confidence is high in the retained commands, results and dependency identities.

## Reproduce and inspect

Run `bash scripts/check-chio-ts-release.sh` with the pinned tools first on PATH. Run the exact OSV command from `.github/workflows/cve-monitor.yml` against a clean checkout with scanner 2.3.6 and the unchanged configuration. Run the conformance workspace test/lint commands separately to reproduce its fixture regression.

`source-manifest.json` identifies every changed manifest, lockfile and test used in this qualification. `raw-evidence.tar.gz` preserves baseline failures, attempted resolutions, final scanner commands/results, complete driver output and dependency graph comparisons. `raw-manifest.json` binds each original payload. Earlier failed attempts are historical observations; later passing evidence does not erase them.
