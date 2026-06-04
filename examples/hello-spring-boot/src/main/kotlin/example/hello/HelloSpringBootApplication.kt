package example.hello

import world.chio.ChioFilter
import world.chio.ChioFilterConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.core.Ordered

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
            addUrlPatterns("/hello", "/echo")
            order = Ordered.HIGHEST_PRECEDENCE
        }
    }
}

fun main(args: Array<String>) {
    runApplication<HelloSpringBootApplication>(*args)
}
