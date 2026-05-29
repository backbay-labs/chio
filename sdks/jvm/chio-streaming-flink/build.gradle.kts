import java.time.Duration

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
        // Pull in main + test outputs so integration tests can reuse the support
        // doubles (FakeChioClient, FakeDlqRouter, FakeRuntimeContext) that live
        // under src/test/kotlin/.../support/.
        compileClasspath +=
            sourceSets.main.get().output +
            sourceSets.test.get().output +
            configurations.testRuntimeClasspath.get()
        runtimeClasspath += output + compileClasspath
    }
}

val integrationTestImplementation: Configuration by configurations.getting {
    extendsFrom(configurations.testImplementation.get())
}

val integrationTestRuntimeOnly: Configuration by configurations.getting {
    extendsFrom(configurations.testRuntimeOnly.get())
}

dependencies {
    api(project(":chio-sdk-jvm"))
    compileOnly(libs.flink.streaming.java)

    testImplementation(libs.kotlin.test.junit5)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.flink.streaming.java)

    integrationTestImplementation(libs.flink.test.utils)
    integrationTestImplementation(libs.flink.clients)
    integrationTestImplementation(libs.flink.streaming.java)

    // Kafka source/sink connector for the end-to-end Kafka integration test.
    // Version pinned to the Flink 2.x series in gradle/chio.versions.toml.
    // flink-connector-base is `provided` in the connector POM (it carries
    // DeliveryGuarantee + sink2 base classes); we have to declare it
    // explicitly or compilation fails on `Cannot access class
    // 'DeliveryGuarantee'`.
    integrationTestImplementation(libs.flink.connector.kafka)
    integrationTestImplementation(libs.flink.connector.base)

    // Testcontainers-driven Redpanda: no separate `docker compose up` step;
    // only a running Docker daemon is required.
    integrationTestImplementation(libs.testcontainers.core)
    integrationTestImplementation(libs.testcontainers.redpanda)
    integrationTestImplementation(libs.testcontainers.junit.jupiter)

    // Native Kafka client for AdminClient (topic management) plus the
    // standalone consumer/producer used to seed source events and read
    // back receipt + DLQ envelopes from Kafka.
    integrationTestImplementation(libs.kafka.clients)

    // slf4j-simple gives Flink + Kafka + Testcontainers a real logger
    // backend so failures surface in test output instead of NOPLogger
    // swallowing them.
    integrationTestRuntimeOnly(libs.slf4j.simple)

    // Testcontainers pulls commons-compress, which depends on
    // commons-codec at runtime but does not bring it into the compile
    // graph. Without this, Redpanda container start crashes on
    // NoClassDefFoundError: org/apache/commons/codec/Charsets when TC
    // tries to copy files into the container.
    integrationTestRuntimeOnly(libs.commons.codec)
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    compilerOptions {
        freeCompilerArgs.add("-Xjsr305=strict")
        freeCompilerArgs.add("-Xannotation-default-target=param-property")
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_21)
    }
}

// Default `test` task: skip the heavy @Tag("integration") suite (default
// CI never spins up Docker / a MiniCluster). Scoping the exclude to ONLY
// `tasks.named("test")` (instead of `withType<Test>().configureEach`)
// avoids the JUnit platform "tag is both included and excluded" warning
// on the integrationTest task, which would silently exclude every test
// because exclude wins over include.
tasks.named<Test>("test").configure {
    useJUnitPlatform {
        excludeTags("integration")
    }
}

/**
 * Runs the Kafka end-to-end @Tag("integration") suite (Flink MiniCluster
 * + Testcontainers Redpanda). Heavy: starts a Docker container and a
 * real Flink MiniCluster, so it is NOT wired to `check` and must be
 * invoked explicitly:
 *
 *   ./gradlew :chio-streaming-flink:integrationTest
 *
 * Requires a running Docker daemon (Testcontainers manages container
 * lifecycle, so no `docker compose up` step is needed).
 *
 * Class-name filter: scoped to the Kafka end-to-end IT to keep the task
 * focused. Other @Tag("integration") files in src/integrationTest/ are
 * left out of this task on purpose; running them is the writer's
 * responsibility.
 */
val integrationTest by tasks.registering(Test::class) {
    description = "Runs Flink MiniCluster + Testcontainers Kafka integration tests."
    group = "verification"
    testClassesDirs = sourceSets["integrationTest"].output.classesDirs
    classpath = sourceSets["integrationTest"].runtimeClasspath
    useJUnitPlatform { includeTags("integration") }
    shouldRunAfter("test")
    systemProperty("junit.jupiter.execution.parallel.enabled", "false")
    // Container pulls + Flink MiniCluster bring-up dwarf the per-test
    // body work; bound the whole task (5 min) so a stuck container does
    // not hang CI runners forever.
    timeout.set(Duration.ofMinutes(5))
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = false
        exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
    }
}
// Deliberately NOT wiring check -> integrationTest; CI skips integration tests.
