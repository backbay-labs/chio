plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.spring) apply false
    alias(libs.plugins.springBoot) apply false
    alias(libs.plugins.spotless) apply false
}

allprojects {
    group = "world.chio"
    version = "0.1.0"
    repositories { mavenCentral() }
}

subprojects {
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
