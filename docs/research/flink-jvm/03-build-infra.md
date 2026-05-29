# Gradle Build + Test Infrastructure for `chio-sdk-jvm` and `chio-streaming-flink-jvm`

Research notes for adding two new JVM modules to `standalone/arc`. Complements
`docs/research/flink/01-flink-internals.md` and `docs/research/flink/02-pyflink-api.md`
(which cover PyFlink); this document is strictly about the JVM build story.

## Summary recommendation

Promote `sdks/jvm/` to a **multi-project Gradle build** with a root
`sdks/jvm/settings.gradle.kts` that includes `chio-sdk-jvm`, `chio-spring-boot`,
and `chio-streaming-flink-jvm`. Keep `examples/hello-spring-boot` as a separate
build that continues to use `includeBuild("../../sdks/jvm")` (it is already a
composite build today, cited below). Use **Kotlin** for both new modules to
match `chio-spring-boot`. Introduce **`gradle/libs.versions.toml`** at
`sdks/jvm/gradle/libs.versions.toml` to centralise Kotlin 2.3.0, Flink 2.2.0,
Jackson, and JUnit pins. Adopt **Spotless + ktlint** for formatting (Kotlin
convention, pluggable into Gradle, matches the repo's "formatter enforced in
CI" posture from `cargo fmt --check`). Use **JUnit 5** via
`useJUnitPlatform()` (already the pattern in `chio-spring-boot/build.gradle.kts`),
with a separate `integrationTest` source set for Flink mini-cluster tests so
fast unit tests stay on the default `test` task. **No publishing block exists
today**; publishing is out of scope for this work but the coordinates pattern
from `chio-spring-boot` (`world.chio:<artifact>:0.1.0`) should be
preserved when it lands. **CI currently runs zero JVM jobs**; a new
`jvm-build` job must be added to `.github/workflows/ci.yml`. The one-liner
for JVM work is `(cd sdks/jvm && ./gradlew build check)`.

## Detailed answers

### 1. Gradle build layout

Evidence from reading the existing files:

- `sdks/jvm/chio-spring-boot/settings.gradle.kts` is a one-liner:
  `rootProject.name = "chio-spring-boot"`. No `include(...)`, no
  `pluginManagement` block. It is a single-project Gradle build.
- `examples/hello-spring-boot/settings.gradle.kts` already uses
  `includeBuild("../../sdks/jvm/chio-spring-boot")`, i.e. it is a composite
  build consuming the SDK as a source dep. It resolves
  `world.chio:chio-spring-boot:0.1.0` through the substitution Gradle
  derives from the included build's `group`/`version`/`rootProject.name`.
- `examples/hello-spring-boot/run.sh` invokes the SDK's wrapper
  (`${SDK_ROOT}/gradlew --no-daemon -p "${EXAMPLE_ROOT}" bootRun`), which
  works because the SDK ships its own wrapper jar under
  `sdks/jvm/chio-spring-boot/gradle/wrapper/`.

Three options considered:

| Option | Fit |
|---|---|
| Multi-project build rooted at `sdks/jvm/` | Recommended. |
| Composite build (each module standalone, `includeBuild`) | Noisy: three wrappers, three `settings.gradle.kts`, three version catalogs. |
| Keep standalone + Maven coordinates | Forces early publication to a real Maven repo; blocks iteration. |

A multi-project build at `sdks/jvm/` keeps one wrapper, one
`libs.versions.toml`, one Spotless config, and one command (`./gradlew build`)
that covers all JVM modules. The existing `chio-spring-boot` wrapper
(`gradle-wrapper.properties: gradle-8.7-bin.zip`) is moved up one level.
`examples/hello-spring-boot` continues to work unchanged because
`includeBuild("../../sdks/jvm")` resolves the full multi-project build; the
Gradle substitution engine maps `world.chio:chio-spring-boot:0.1.0` to
the `chio-spring-boot` subproject automatically.

One wrinkle: **`chio-streaming-flink-jvm` depends on `flink-streaming-java`,
which does not work under Java 17 consistently for all connectors.** Flink
2.2 supports JDK 21 (that's what this repo has installed), and the existing
modules target `JVM_17` as their bytecode level. The new Flink module will
target JDK 21 bytecode (`JavaVersion.VERSION_21`). A multi-project build
handles heterogenous JVM targets cleanly via per-subproject
`java { targetCompatibility = ... }`.

### 2. Version catalog

`chio-spring-boot/build.gradle.kts` hard-codes every version (Kotlin 2.3.0,
Spring Boot 3.2.2). There is no `libs.versions.toml` anywhere in the repo
(confirmed by `find ... -name libs.versions.toml`). Introduce one at
`sdks/jvm/gradle/libs.versions.toml`. Benefits: single place to bump Kotlin
across `chio-sdk-jvm` + `chio-spring-boot` + `chio-streaming-flink-jvm`; matches
the concrete versions we pin in section 9; Gradle's type-safe accessors
(`libs.kotlin.stdlib`) catch typos at configuration time.

### 3. Kotlin JVM target vs Java

`chio-spring-boot/build.gradle.kts` uses Kotlin with
`kotlin("jvm") version "2.3.0"`, `jvmTarget.set(JVM_17)`, and
`freeCompilerArgs.add("-Xjsr305=strict")`. Stay on Kotlin for both new modules.
Rationale: consistency with the one existing JVM module; Kotlin's data classes
mirror the Rust `Capability`/`Receipt` structs cleanly; Flink's Java API is
fully usable from Kotlin (`org.apache.flink.streaming.api.datastream.DataStream`
returns `DataStream<T>` with no Kotlin-unfriendly bounds). Minimal template is
in the "Proposed Gradle skeletons" section.

### 4. Lint / format

Evidence: no `.editorconfig`, no `.ktlint*`, no `detekt*`, no `spotless*`, no
Checkstyle config anywhere in the repo (search confirmed). The only
formatter enforcement is `cargo fmt --all -- --check` in
`.github/workflows/ci.yml` (Rust) and `ruff format`/`mypy` for Python.

Recommendation: **Spotless with the ktlint engine**. Spotless is the
de-facto "one formatter plugin to rule them all" for Gradle. The ktlint
engine gives us Kotlin formatting without writing our own rule set and
integrates with `./gradlew check` so CI catches unformatted code the same
way `cargo fmt --check` does. Minimal Spotless block:

```kotlin
spotless {
    kotlin {
        ktlint("1.5.0")
        target("src/**/*.kt")
    }
    kotlinGradle {
        ktlint("1.5.0")
        target("*.gradle.kts")
    }
}
```

Detekt is heavier (static analysis, not formatting) and can be added later
if needed; do not adopt both up front.

### 5. Testing

Current `chio-spring-boot/build.gradle.kts` already has:

```kotlin
tasks.withType<Test> {
    useJUnitPlatform()
}
```

Keep this. For `chio-streaming-flink-jvm` integration tests
(`flink-test-utils` spins up a `MiniClusterWithClientResource`), create a
**separate `integrationTest` source set** so unit tests stay fast on the
default `test` task:

```kotlin
sourceSets {
    create("integrationTest") {
        compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
        runtimeClasspath += output + compileClasspath
    }
}
val integrationTest by tasks.registering(Test::class) {
    description = "Runs Flink mini-cluster integration tests."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter("test")
    systemProperty("junit.jupiter.execution.parallel.enabled", "false")
}
tasks.named("check") { dependsOn(integrationTest) }
```

Integration tests run serially (`parallel.enabled = false`); MiniCluster
state is not thread-safe across concurrent test classes. Unit tests keep the
default settings and can opt into parallel execution later if any turn up as
slow. Tag-based separation (`@Tag("integration")`) is a lighter alternative,
but separate source sets give cleaner classpath isolation for the Flink test
jars.

### 6. Publishing

`chio-spring-boot/build.gradle.kts` has **no `publishing { }` block, no
`maven-publish` plugin, no `signing` plugin**. The artifact coordinates
`world.chio:chio-spring-boot:0.1.0` exist only because Gradle synthesises
them from `group` + `rootProject.name` + `version` when the SDK is consumed
via `includeBuild`. Nothing is pushed to Maven Central or GitHub Packages.

Recommendation: **publishing is out of scope for this work.** When the
eventual 0.1.0 JVM release lands, adopt the `maven-publish` plugin with
`world.chio:chio-sdk-jvm:<v>`,
`world.chio:chio-spring-boot:<v>`,
`world.chio:chio-streaming-flink-jvm:<v>`. Keep `group = "world.chio"`
and a unified `version` across modules. Track in the release epic; not here.

### 7. CI integration

`.github/workflows/ci.yml` currently runs `check`, `msrv`, and `coverage`
jobs, all Rust / Python / Lean. **No JVM job exists.** The workflow does not
install a JDK, does not invoke Gradle, and does not touch `sdks/jvm/`.

A new `jvm-build` job is needed:

```yaml
  jvm-build:
    name: JVM build and test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: "21"
      - uses: gradle/actions/setup-gradle@v4
      - name: Build and test JVM modules
        working-directory: sdks/jvm
        run: ./gradlew build check --no-daemon
```

Trigger: the same `push` + `pull_request` on `main` as the existing jobs.
`gradle/actions/setup-gradle@v4` handles wrapper caching; no custom cache
key needed. Run after the Rust `check` job or in parallel; there is no
shared state.

### 8. One-liner build + test command

Sibling to the Rust one-liner in the repo `CLAUDE.md`:

```bash
(cd sdks/jvm && ./gradlew build check spotlessCheck --no-daemon)
```

`build` compiles + runs unit tests; `check` triggers `integrationTest` in the
Flink module (the `check.dependsOn(integrationTest)` wiring above);
`spotlessCheck` fails on unformatted Kotlin. `--no-daemon` matches
`examples/hello-spring-boot/run.sh` and is preferred in CI / one-shot
scripts.

### 9. Dependency pins to recommend

Confirmed against Maven Central directory listings
(`repo1.maven.org/maven2/org/apache/flink/...`) on 2026-04-23:

| Artifact | Version | Notes |
|---|---|---|
| `org.apache.flink:flink-streaming-java` | `2.2.0` | Standardised. Confirmed present at `.../flink-streaming-java/2.2.0/`. |
| `org.apache.flink:flink-clients` | `2.2.0` | Needed for local execution in tests. |
| `org.apache.flink:flink-connector-kafka` | `4.0.1-2.0` | Latest on central. The `-2.0` suffix = Flink 2.x line (forward-compatible with 2.2). POM (`flink-connector-kafka-parent:4.0.1-2.0`) pins `<flink.version>2.0.0</flink.version>` and `<kafka.version>3.9.1</kafka.version>`; works against Flink 2.2 per the Flink externalised-connector compatibility guarantee. No `-2.2`-suffixed release exists yet. |
| `org.apache.flink:flink-test-utils` | `2.2.0` | Confirmed present at `.../flink-test-utils/2.2.0/`. Provides `MiniClusterWithClientResource`. |
| `org.apache.flink:flink-connector-kafka` test jar | `4.0.1-2.0` (classifier `tests`) | Kafka container harness for integration tests. |
| `com.fasterxml.jackson.module:jackson-module-kotlin` | transitive via `spring-boot-dependencies:3.2.2` BOM (Jackson 2.15.x) for `chio-spring-boot`; for the Flink module pin directly to `2.17.2` (matches Flink 2.2's `flink-shaded-jackson`). |
| `org.junit.jupiter:junit-jupiter` | `5.11.4` | What `flink-streaming-java:2.2.0` pins internally. Use the same for the Flink module to avoid surface mismatch. `chio-spring-boot` keeps the Spring Boot BOM's 5.10.x. |
| `org.jetbrains.kotlin:kotlin-stdlib` / Kotlin plugin | `2.3.0` | Matches `chio-spring-boot/build.gradle.kts` line 2. |

Do not let the Flink module pull in `spring-boot-dependencies`; it has no
Spring surface area and the BOM would force older Jackson.

## Proposed Gradle skeletons

Drop-in files. Treat as **recommendations**, not final code; version numbers
match section 9 and are pasted verbatim so the build compiles.

### `sdks/jvm/settings.gradle.kts` (new)

```kotlin
pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_PROJECT)
    repositories {
        mavenCentral()
    }
    versionCatalogs {
        create("libs") {
            from(files("gradle/libs.versions.toml"))
        }
    }
}

rootProject.name = "chio-jvm"

include(":chio-sdk-jvm")
include(":chio-spring-boot")
include(":chio-streaming-flink-jvm")
```

### `sdks/jvm/gradle/libs.versions.toml` (new)

```toml
[versions]
kotlin = "2.3.0"
springBoot = "3.2.2"
flink = "2.2.0"
flinkKafka = "4.0.1-2.0"
jackson = "2.17.2"
junit = "5.11.4"
spotless = "7.0.2"
ktlint = "1.5.0"

[libraries]
kotlin-stdlib = { module = "org.jetbrains.kotlin:kotlin-stdlib", version.ref = "kotlin" }
kotlin-reflect = { module = "org.jetbrains.kotlin:kotlin-reflect", version.ref = "kotlin" }
kotlin-test-junit5 = { module = "org.jetbrains.kotlin:kotlin-test-junit5", version.ref = "kotlin" }

jackson-module-kotlin = { module = "com.fasterxml.jackson.module:jackson-module-kotlin", version.ref = "jackson" }

springBoot-bom = { module = "org.springframework.boot:spring-boot-dependencies", version.ref = "springBoot" }
springBoot-starter-web = { module = "org.springframework.boot:spring-boot-starter-web" }
springBoot-starter-test = { module = "org.springframework.boot:spring-boot-starter-test" }

flink-streaming-java = { module = "org.apache.flink:flink-streaming-java", version.ref = "flink" }
flink-clients = { module = "org.apache.flink:flink-clients", version.ref = "flink" }
flink-connector-kafka = { module = "org.apache.flink:flink-connector-kafka", version.ref = "flinkKafka" }
flink-test-utils = { module = "org.apache.flink:flink-test-utils", version.ref = "flink" }

junit-jupiter = { module = "org.junit.jupiter:junit-jupiter", version.ref = "junit" }

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
kotlin-spring = { id = "org.jetbrains.kotlin.plugin.spring", version.ref = "kotlin" }
springBoot = { id = "org.springframework.boot", version.ref = "springBoot" }
spotless = { id = "com.diffplug.spotless", version.ref = "spotless" }
```

### `sdks/jvm/build.gradle.kts` (new root convention)

```kotlin
plugins {
    alias(libs.plugins.spotless) apply false
}

subprojects {
    group = "world.chio"
    version = "0.1.0"

    apply(plugin = "com.diffplug.spotless")

    extensions.configure<com.diffplug.gradle.spotless.SpotlessExtension> {
        kotlin {
            ktlint(rootProject.libs.versions.ktlint.get())
            target("src/**/*.kt")
        }
        kotlinGradle {
            ktlint(rootProject.libs.versions.ktlint.get())
            target("*.gradle.kts")
        }
    }
}
```

### `sdks/jvm/chio-sdk-jvm/build.gradle.kts` (new, minimal Kotlin library)

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

dependencies {
    api(libs.kotlin.stdlib)
    api(libs.jackson.module.kotlin)

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit.jupiter)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.withType<Test> { useJUnitPlatform() }
```

### `sdks/jvm/chio-streaming-flink-jvm/build.gradle.kts` (new)

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

sourceSets {
    create("integrationTest") {
        compileClasspath += sourceSets.main.get().output + configurations.testRuntimeClasspath.get()
        runtimeClasspath += output + compileClasspath
    }
}

val integrationTestImplementation by configurations.getting {
    extendsFrom(configurations.testImplementation.get())
}

dependencies {
    api(project(":chio-sdk-jvm"))
    api(libs.flink.streaming.java)
    implementation(libs.flink.connector.kafka)
    implementation(libs.jackson.module.kotlin)

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit.jupiter)

    integrationTestImplementation(libs.flink.test.utils)
    integrationTestImplementation(libs.flink.clients)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

tasks.withType<Test> { useJUnitPlatform() }

val integrationTest by tasks.registering(Test::class) {
    description = "Runs Flink MiniCluster integration tests."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform()
    shouldRunAfter("test")
    systemProperty("junit.jupiter.execution.parallel.enabled", "false")
}
tasks.named("check") { dependsOn(integrationTest) }
```

### `sdks/jvm/chio-spring-boot/build.gradle.kts` (refactored to use catalog)

```kotlin
plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.spring)
    alias(libs.plugins.springBoot) apply false
}

java { sourceCompatibility = JavaVersion.VERSION_17 }

dependencies {
    implementation(platform(libs.springBoot.bom))
    implementation(libs.springBoot.starter.web)
    implementation(libs.jackson.module.kotlin)
    implementation(libs.kotlin.reflect)

    testImplementation(platform(libs.springBoot.bom))
    testImplementation(libs.springBoot.starter.test)
    testImplementation(libs.kotlin.test.junit5)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

tasks.withType<Test> { useJUnitPlatform() }
```

Wrapper lives at `sdks/jvm/gradle/wrapper/` (moved up from
`sdks/jvm/chio-spring-boot/gradle/wrapper/`). `examples/hello-spring-boot/settings.gradle.kts`
updates to `includeBuild("../../sdks/jvm")` (currently `../../sdks/jvm/chio-spring-boot`).

## One-liner build + test command

```bash
(cd sdks/jvm && ./gradlew build check spotlessCheck --no-daemon)
```

Add to the repo `CLAUDE.md` alongside the Rust one-liner. In CI use the same
command; add the `jvm-build` job sketched in section 7.

## Open questions

- **Gradle 9.x vs 8.7.** The host has Gradle 9.x installed (`/opt/homebrew/bin/gradle`) but the wrapper pins 8.7. Upgrading the wrapper to 9.x is straightforward and will improve Kotlin 2.3 performance, but the Spring Boot 3.2.2 plugin is only tested through Gradle 8.x; confirm by running `./gradlew wrapper --gradle-version 9.0` on a branch before flipping the pin. Leaving the wrapper at 8.7 is a safe default.
- **Kafka connector version hedge.** `flink-connector-kafka:4.0.1-2.0` is the only 2.x-suffixed release on Maven Central. If a `-2.2`-suffixed release ships before our module goes to main, switch to it. Pin-via-catalog makes this a one-line bump.
- **Integration-test isolation.** Flink MiniCluster acquires free ports and can clash with `examples/hello-spring-boot/smoke.sh` (which also grabs free ports with `pick_free_port`). If CI ever runs both in parallel on the same runner, add `maxParallelForks = 1` at the `integrationTest` task level.
- **Jackson version drift.** Flink 2.2 uses `flink-shaded-jackson` internally, but any Chio envelope serialisation we do must not leak into the shaded namespace. Pinning `com.fasterxml.jackson.module:jackson-module-kotlin:2.17.2` is safe because Flink's shading relocates its copy to `org.apache.flink.shaded.jackson2.*`. Confirm on first integration test run.
- **Publishing coordinates.** Out of scope for this work, but worth ratifying before code review: `world.chio:chio-sdk-jvm:0.1.0` (pure Kotlin), `world.chio:chio-spring-boot:0.1.0` (Spring adapter), `world.chio:chio-streaming-flink-jvm:0.1.0` (Flink adapter). Matches the Python `chio_streaming[flink]` naming from `docs/research/chio-streaming-flink-integration.md`.
