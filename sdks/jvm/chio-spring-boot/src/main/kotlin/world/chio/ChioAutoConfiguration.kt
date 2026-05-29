/**
 * Spring Boot auto-configuration for Chio protection.
 *
 * Automatically registers the Chio servlet filter as a bean when the
 * spring-boot-starter is on the classpath. Configuration is read from
 * application.properties/yaml under the `chio` prefix.
 *
 * Usage in application.properties:
 *   chio.sidecar-url=http://127.0.0.1:9090
 *   chio.timeout-seconds=5
 *   chio.on-sidecar-error=deny
 */
package world.chio

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

/** Configuration properties for the Chio filter. */
@ConfigurationProperties(prefix = "chio")
data class ChioProperties(
    /** Base URL of the Chio sidecar kernel. */
    val sidecarUrl: String = System.getenv("CHIO_SIDECAR_URL") ?: "http://127.0.0.1:9090",
    /** HTTP timeout for sidecar calls in seconds. */
    val timeoutSeconds: Long = 5,
    /** Behavior when sidecar is unreachable: "deny" (fail-closed) or "allow" (fail-open). */
    val onSidecarError: String = "deny",
    /** Whether Chio protection is enabled. Defaults to true. */
    val enabled: Boolean = true,
    /** URL patterns to protect. Defaults to all routes. */
    val urlPatterns: List<String> = listOf("/*"),
    /** Filter order. Lower values run first. */
    val filterOrder: Int = 1,
)

/** Spring Boot auto-configuration for Chio protection. */
@Configuration
@EnableConfigurationProperties(ChioProperties::class)
@ConditionalOnClass(ChioFilter::class)
@ConditionalOnProperty(prefix = "chio", name = ["enabled"], havingValue = "true", matchIfMissing = true)
open class ChioAutoConfiguration {
    @Bean
    open fun chioFilterRegistration(properties: ChioProperties): FilterRegistrationBean<ChioFilter> {
        val config =
            ChioFilterConfig(
                sidecarUrl = properties.sidecarUrl,
                timeoutSeconds = properties.timeoutSeconds,
                onSidecarError = properties.onSidecarError,
            )

        val filter = ChioFilter(config)
        val registration = FilterRegistrationBean(filter)
        registration.urlPatterns = properties.urlPatterns
        registration.order = properties.filterOrder
        registration.setName("chioFilter")
        return registration
    }
}
