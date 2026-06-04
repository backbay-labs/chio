package example.hello

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest
import org.springframework.http.MediaType
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@WebMvcTest(HelloController::class)
@AutoConfigureMockMvc(addFilters = false)
class HelloControllerTest {
    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun `healthz route bypass shape`() {
        mockMvc.perform(get("/healthz"))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.status").value("ok"))
    }

    @Test
    fun `hello route returns no receipt header without filter`() {
        mockMvc.perform(get("/hello"))
            .andExpect(status().isOk)
            .andExpect(header().doesNotExist("X-Chio-Receipt-Id"))
            .andExpect(jsonPath("$.message").value("hello from spring-boot"))
    }

    @Test
    fun `echo defaults count`() {
        mockMvc.perform(
            post("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"message":"hello"}"""),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.message").value("hello"))
            .andExpect(jsonPath("$.count").value(1))
    }

    @Test
    fun `echo rejects non-object bodies`() {
        mockMvc.perform(
            post("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""["hello"]"""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("body must be a JSON object"))
    }

    @Test
    fun `echo rejects empty messages`() {
        mockMvc.perform(
            post("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"message":"","count":1}"""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("message must be a non-empty string"))
    }

    @Test
    fun `echo rejects coerced counts`() {
        mockMvc.perform(
            post("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"message":"hello","count":"2"}"""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("count must be an integer greater than or equal to 1"))
    }

    @Test
    fun `echo rejects extra fields`() {
        mockMvc.perform(
            post("/echo")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""{"message":"hello","count":1,"admin":true}"""),
        )
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error").value("unexpected fields: admin"))
    }
}
