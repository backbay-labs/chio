// JVM SDK verdict-matrix driver.
//
// This Gradle project is a deployment-shape driver for the Chio verdict
// matrix. It re-hosts the `sdks/jvm/chio-sdk-jvm` host bindings behind a
// Kotlin entry point that loads the canonical scenario corpus and emits the
// (verdict, reason_code, scope_set) tuple per scenario by forwarding each
// scenario to a Chio sidecar over POST /chio/evaluate. The driver is
// registered as a `transport-client` deployment-shape entry in the parent
// verdict-matrix manifest; active execution is gated on an operator-supplied
// sidecar URL via the `CHIO_VERDICT_MATRIX_SIDECAR_URL` environment variable,
// mirroring the TypeScript node-http driver contract.

plugins {
    kotlin("jvm") version "2.0.21"
    application
}

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.jetbrains.kotlin:kotlin-stdlib:2.0.21")
    implementation("com.fasterxml.jackson.module:jackson-module-kotlin:2.18.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.1")

    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5:2.0.21")
    testImplementation("org.junit.jupiter:junit-jupiter:5.11.3")
}

application {
    mainClass.set("world.chio.verdictmatrix.jvm.DriverKt")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}
