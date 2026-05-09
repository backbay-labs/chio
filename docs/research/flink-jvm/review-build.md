# JVM Flink Integration Review: Build + Tests

## Summary

The multi-project Gradle layout at `sdks/jvm/` is sound: `./gradlew build`,
`./gradlew spotlessCheck`, and `./gradlew :chio-streaming-flink:integrationTestClasses`
all pass on a fresh invocation against JDK 21. 18 unit-test classes run (~114
assertions total), including the Python-vector canonical JSON cases and
`denyYieldsDlqOnlyNoReceipt`. Dependency scoping is largely correct:
`chio-sdk-jvm` pulls in only Kotlin + Jackson, and `chio-streaming-flink`
declares `flink-streaming-java` as `compileOnly` so runtimeClasspath excludes
Flink. The new `jvm-build` CI job is wired to Temurin 21 and the Gradle action.

Two issues rise to P1: (a) the companion `examples/hello-spring-boot` was not
updated when the wrapper moved, so that composite build is now broken, and
(b) the root `settings.gradle.kts` omits the version-catalog `from(...)`
block referenced by `03-build-infra.md`, yet accessors resolve because
`gradle/libs.versions.toml` is picked up by Gradle 8.x convention -- this is
fragile and will break if the catalog is renamed or Gradle 9 tightens.
Several P2/P3 items around `api` semantics on the Kotlin-only module,
CI not invoking `spotlessCheck`, module READMEs, and a large pile of
Kotlin 2.3 annotation-target warnings.

## Build verification

Commands run from `sdks/jvm` with `JAVA_HOME=/opt/homebrew/opt/openjdk@21`:

- `./gradlew --version` -> Gradle 8.7, JVM 21.0.10. Matches plan.
- `./gradlew projects --no-daemon` -> root `chio-jvm` with subprojects
  `:chio-sdk-jvm`, `:chio-spring-boot`, `:chio-streaming-flink`. OK.
- `./gradlew build --no-daemon` -> SUCCESSFUL in 5s (cached) / ~17s cold.
  All 13 actionable tasks pass.
- `./gradlew spotlessCheck --no-daemon` -> SUCCESSFUL.
- `./gradlew :chio-streaming-flink:integrationTestClasses --no-daemon` ->
  SUCCESSFUL; both `MiniClusterSyncJobIT.kt` and `MiniClusterAsyncJobIT.kt`
  compile against the `integrationTest` source set.
- `./gradlew :chio-sdk-jvm:dependencies --configuration runtimeClasspath`
  shows only `kotlin-stdlib`, `kotlin-reflect`, `jackson-databind`, and
  `jackson-module-kotlin`. No Spring, no Flink. Pass.
- `./gradlew :chio-streaming-flink:dependencies --configuration runtimeClasspath`
  shows only the `:chio-sdk-jvm` project + `kotlin-stdlib`. Flink is
  `compileOnly`, confirmed.
- `./gradlew :chio-streaming-flink:dependencies --configuration compileClasspath`
  shows Flink 2.2.0 + its transitive shaded artefacts, plus Jackson
  (propagated through `api(project(":chio-sdk-jvm"))`). Pass.
- `grep -rn $'\xe2\x80\x94' sdks/jvm --include='*.kt' --include='*.kts' --include='*.md' --include='*.toml'` -> no matches. Em-dash rule clean.
- `./gradlew build --warning-mode=all --rerun-tasks` -> 78 Kotlin compiler
  warnings emitted (see Findings).

## Findings

### [P1] `examples/hello-spring-boot` composite build points at deleted path

File: `examples/hello-spring-boot/settings.gradle.kts:17` and
`examples/hello-spring-boot/run.sh:5`.

Both still reference `../../sdks/jvm/chio-spring-boot`, which is no longer a
standalone Gradle build: `sdks/jvm/chio-spring-boot/settings.gradle.kts`
is gone (subproject now), no wrapper sits there, and
`${SDK_ROOT}/gradlew` does not exist. Running `examples/hello-spring-boot/run.sh`
will fail on a clean checkout. The implementation plan
(`04-implementation-plan.md:123-124`) explicitly calls out the flip to
`includeBuild("../../sdks/jvm")` and mentions `run.sh` still references the
old wrapper. Both files need updating alongside this PR to keep the
example runnable.

Fix: change the include to `includeBuild("../../sdks/jvm")` and update
`run.sh` to `SDK_ROOT="$(cd "${EXAMPLE_ROOT}/../../sdks/jvm" && pwd)"`.

### [P1] Root `settings.gradle.kts` does not declare the version catalog

File: `sdks/jvm/settings.gradle.kts:8-11`.

The `dependencyResolutionManagement` block omits the
`versionCatalogs { create("libs") { from(files("gradle/libs.versions.toml")) } }`
stanza from `03-build-infra.md:256-265`. It currently works because Gradle
auto-registers a catalog named `libs` when a file at
`gradle/libs.versions.toml` exists, but this is a convention and is brittle:
rename the file or move it and every `alias(libs.plugins.*)` silently fails
to resolve. An explicit `versionCatalogs { create("libs") { from(files(...)) } }`
block locks the source.

Fix: add the `versionCatalogs` block inside `dependencyResolutionManagement`.

### [P2] `chio-spring-boot` does not apply `java-library`, so `api(...)` is
half-wired

File: `sdks/jvm/chio-spring-boot/build.gradle.kts:1-5`.

`chio-sdk-jvm` correctly applies `` `java-library` `` and `api(project(...))`
propagates Jackson to `chio-streaming-flink`'s compileClasspath. But
`chio-spring-boot` applies only `kotlin-jvm` + `kotlin-spring`. The Kotlin
Gradle plugin does register an `api` configuration, so declaration compiles,
but the `apiElements` outgoing variant is owned by the `java` plugin and
does not propagate `api` unless `java-library` is also applied. Effect: a
hypothetical downstream module that consumes `chio-spring-boot` will not
see `chio-sdk-jvm` types on its compileClasspath without re-declaring them.
`runtimeElements` still propagates (confirmed via
`:chio-spring-boot:dependencies --configuration runtimeClasspath` showing
`project :chio-sdk-jvm`), so runtime works, but compile-time does not.

Plan said (`04-implementation-plan.md`) `chio-spring-boot` re-exposes SDK
types to keep downstream consumers compiling. It should:

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.springBoot) apply false
    `java-library`
}
```

### [P2] `jvm-build` CI job does not exercise spotless or integration tests

File: `.github/workflows/ci.yml:33-35`.

Runs `./gradlew build --no-daemon` only. `build` triggers `spotlessCheck`
through `check` transitively (verified via task graph), but does not run
`integrationTest` because the new Flink module deliberately omits
`check.dependsOn(integrationTest)` (`chio-streaming-flink/build.gradle.kts:57`:
"Deliberately NOT wiring check -> integrationTest; CI skips integration tests.").
That is intentional. However the plan's one-liner in `03-build-infra.md:210-213`
is `./gradlew build check spotlessCheck`. Dropping `spotlessCheck` from CI
is fine because `check` already depends on it, but an explicit
`spotlessCheck` invocation would make CI fail fast on formatting issues
before spending time on compile + test.

Also: the job has no `paths:` filter, so it runs on every push to `main` /
every PR. That's consistent with the Rust `check` job, so acceptable, but
adding `paths: [sdks/jvm/**, .github/workflows/ci.yml]` would speed up
non-JVM PRs.

### [P2] 78 Kotlin 2.3 annotation-target warnings pending promotion to errors

File: pervasive across `chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/*.kt`
(~60 in `ChioReceipt.kt`, `ChioTypes.kt`, `Decision.kt`,
`ToolCallAction.kt`).

Sample:
```
ChioReceipt.kt:16:5 This annotation is currently applied to the value
parameter only, but in the future it will also be applied to field.
To opt in ..., add '-Xannotation-default-target=param-property' to your
compiler arguments.
```

Kotlin 2.3 warns about `@JsonProperty`-style annotations on constructor
properties changing target. The YouTrack ticket linked (KT-73255) ships
this behaviour as an error in Kotlin 2.4. Either add
`-Xannotation-default-target=param-property` to `freeCompilerArgs` or
rewrite each annotation as `@param:JsonProperty(...)`. Doing nothing
means the build breaks the day Kotlin bumps.

Secondary warnings from the same run:

- `ChioClient.kt:68:63` Unchecked cast `Map<*, *>!` to `Map<String, Any?>`.
  Either `@Suppress("UNCHECKED_CAST")` with an inline comment, or validate
  with `mapNotNull { it.key as? String }`.
- `CanonicalJson.kt:59:18` `ObjectMapper.configure(MapperFeature, Boolean)`
  is deprecated. Use `configure(MapperFeature, Boolean)` on a `Builder`
  or switch to `ObjectMapper.enable(...)` / `disable(...)`.
- Three `Unnecessary non-null assertion (!!)` in
  `SyntheticDenyReceiptTest.kt:65,68`,
  `ChioAsyncEvaluateFunctionTest.kt:49`,
  `ChioEvaluateFunctionTest.kt:139:40`.

### [P2] No `@Tag("parity")` marker on the wire-parity unit tests

File: `sdks/jvm/chio-streaming-flink/src/test/kotlin/**/*.kt`.

`02-flink-operator-design.md:315` calls for "Wire-parity tests (tagged
`parity`)" and references 14 invariants. `grep -rn "@Tag" sdks/jvm/chio-streaming-flink/src/test`
returns nothing. The deny-path parity is covered by name (e.g.
`denyYieldsDlqOnlyNoReceipt`, `denyEmitsOnlyDlqNoReceipt`,
`denyBehaviourSynthesisesMarkerReceiptAndDlq`) and the tests pass, but
they're not easily selectable as a bundle. If the 14-invariant list lives
anywhere it should be cross-referenced from the test class KDoc.

Fix: add `@Tag("parity")` to the relevant tests and either create a
`parityTest` Gradle task (`includeTags("parity")`) or at minimum document
the invariant-to-test mapping in a module README.

### [P2] Kotlin plugin applied redundantly in two subprojects

Build log: "The Kotlin Gradle plugin was loaded multiple times in different
subprojects." Raised on every invocation.

File: `chio-sdk-jvm/build.gradle.kts:2`, `chio-spring-boot/build.gradle.kts:2`,
`chio-streaming-flink/build.gradle.kts:2`.

All three subprojects call `alias(libs.plugins.kotlin.jvm)`. Gradle loads
the Kotlin Gradle plugin into each project's classpath separately, which it
officially does not support. Fix per Gradle's own guidance: apply the
plugin at the root with `apply false`:

```kotlin
// root build.gradle.kts
plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.spring) apply false
    alias(libs.plugins.springBoot) apply false
    alias(libs.plugins.spotless) apply false
}
```

Subprojects keep `alias(libs.plugins.kotlin.jvm)` (no `apply false`).

### [P3] No `README.md` in `chio-sdk-jvm` or `chio-streaming-flink`

Files: `sdks/jvm/chio-sdk-jvm/` (missing), `sdks/jvm/chio-streaming-flink/`
(missing). `chio-spring-boot/README.md` exists and is solid.

`03-build-infra.md` does not strictly require them, but `04-implementation-plan.md`
section 1 lists `chio-spring-boot/README.md` explicitly; the two new modules
should get parallel quickstarts (install, JDK requirements, `ChioFlinkConfig`
example for the Flink module, `ChioClient` example for the SDK).

### [P3] No package-level KDoc

File: `sdks/jvm/chio-sdk-jvm/src/main/kotlin/io/backbay/chio/sdk/`, same for
`chio-streaming-flink`.

There is no `package.kt` / module-level summary file. Each source file has
a KDoc but there's no single entry point for someone browsing Dokka output.
A `Package.kt` with a single `/** High-level summary ... */` block
improves discoverability at effectively zero cost.

### [P3] Thread.sleep present in two tests, both defensible

Files:
- `chio-sdk-jvm/src/test/kotlin/.../ChioClientHttpTest.kt:199` (2000 ms)
  simulates slow sidecar to exercise the 250 ms timeout path; legitimate.
- `chio-streaming-flink/src/test/kotlin/.../ChioFlinkEvaluatorTest.kt:202`
  (200 ms) waits for concurrent threads to contend for the semaphore before
  asserting `admitted <= 2`. This is a race-prone pattern (semaphore
  admission count depends on scheduling); consider `CountDownLatch` to
  block all threads until they've all attempted `tryAcquire`.

### [P3] Integration tests depend on OS-assigned port (port 0)

Files: `MiniClusterSyncJobIT.kt:79`, `MiniClusterAsyncJobIT.kt`.

`InetSocketAddress("127.0.0.1", 0)` asks the kernel for a free port. No
collision risk, but since integration tests are deliberately excluded from
CI (`check` does not depend on `integrationTest`), this is observer-only.
No Kafka broker dependency - the fake sidecar is a `com.sun.net.httpserver.HttpServer`,
which is plain JDK. Good.

### [P3] `chio-spring-boot` emits a self-deprecation warning every compile

File: `ChioFilter.kt:66` -> `ChioSidecarClient(...)` is marked deprecated in
`compat/ChioSidecarClient.kt`. The caller is the filter itself, not a user.
Migrate the internal usage to `io.backbay.chio.sdk.ChioClient` to silence
the warning and mirror the plan's guidance that `ChioSidecarClient` is a
one-release compat shim.

## Non-findings (verified correct)

- `gradle-wrapper.properties` pins `gradle-8.7-bin.zip`; matches plan.
- `libs.versions.toml` uses single Kotlin (`2.3.0`), single JUnit (`5.11.4`),
  single Jackson (`2.17.2`), single Flink (`2.2.0`). No drift between
  subprojects; every version is reached via `libs.versions.*`.
- JDK targets: `chio-sdk-jvm` and `chio-spring-boot` set
  `JavaVersion.VERSION_17` and `JvmTarget.JVM_17` (lines 6-9 / 21-26 of
  both build files). `chio-streaming-flink` sets `VERSION_21` / `JVM_21`.
- `flink-streaming-java` is `compileOnly` in
  `chio-streaming-flink/build.gradle.kts:24`, and still in
  `testImplementation` on line 28 so tests compile.
- `chio-sdk-jvm` runtimeClasspath has zero Spring/Flink leakage.
- Every subproject's `tasks.withType<Test>` block sets `useJUnitPlatform()`.
- `chio-streaming-flink` `integrationTest` source set is wired correctly:
  `includeTags("integration")` on the `integrationTest` task and
  `excludeTags("integration")` on the default `test` task. Integration
  classes are compiled, and the plan's `@Tag("integration")` is applied
  to both MiniCluster tests.
- `CanonicalJsonTest.kt` covers Vector 1 (nested Unicode), Vector 2 (emoji
  surrogate pair), Vector 3 (null map values) -- the exact three the review
  brief asked about. Expected bytes match
  `json.dumps({"arr":[1,"two",{"k":3}],"flag":true,"null_field":null}, sort_keys=True, separators=(",",":"))`.
- `FakeRuntimeContext.kt` (230 lines) provides a proper mock of
  `RuntimeContext` + `OperatorMetricGroup`, plus `FakeChioClient`,
  `FakeDlqRouter`. Operator unit tests do not start a MiniCluster.
- No em-dashes, no proscribed `Thread.sleep` in production code, no
  attempt to start a Kafka broker in CI.
- ktlint pinned to `1.5.0` via `libs.versions.ktlint`, consumed by
  `spotless { kotlin { ktlint(rootProject.libs.versions.ktlint.get()) } }`
  at `sdks/jvm/build.gradle.kts:15,19`.
- Spotless applied once at the root to all subprojects; no duplication.
