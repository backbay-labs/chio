package example.hello

import world.chio.ChioFilter
import world.chio.ChioFilterConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.core.Ordered
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class HelloSpringBootApplication {
    @Bean
    fun chioFilterRegistration(): FilterRegistrationBean<ChioFilter> {
        val filter = ChioFilter(
            ChioFilterConfig(
                sidecarUrl = System.getenv("CHIO_SIDECAR_URL") ?: "http://127.0.0.1:9090",
            ),
        )

        return FilterRegistrationBean<ChioFilter>().apply {
            setFilter(filter)
            addUrlPatterns("/*")
            order = Ordered.HIGHEST_PRECEDENCE
        }
    }
}

@RestController
class HelloController {
    @GetMapping("/healthz")
    fun healthz(): Map<String, String> = mapOf("status" to "ok")

    @GetMapping("/hello")
    fun hello(): Map<String, String> = mapOf("message" to "hello from spring-boot")

    @PostMapping("/echo", consumes = [MediaType.APPLICATION_JSON_VALUE])
    fun echo(@RequestBody payload: EchoRequest): Map<String, Any> = mapOf(
        "message" to payload.message,
        "count" to payload.count,
    )
}

data class EchoRequest(
    val message: String,
    val count: Int = 1,
)

fun main(args: Array<String>) {
    runApplication<HelloSpringBootApplication>(*args)
}
