package world.chio

import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import world.chio.sdk.Hashing.sha256Hex
import kotlin.test.assertEquals

class ChioFilterBodyTest {
    @Test
    fun `cached body request allows repeated reads`() {
        val payload = """{"hello":"world","count":2}"""
        val request =
            MockHttpServletRequest().apply {
                method = "POST"
                requestURI = "/echo"
                contentType = "application/json"
                setContent(payload.toByteArray(Charsets.UTF_8))
            }

        val wrapped = CachedBodyHttpServletRequest(request)
        val firstRead = wrapped.inputStream.readAllBytes().toString(Charsets.UTF_8)
        val secondRead = wrapped.inputStream.readAllBytes().toString(Charsets.UTF_8)

        assertEquals(payload, firstRead)
        assertEquals(payload, secondRead)
        assertEquals(sha256Hex(payload.toByteArray(Charsets.UTF_8)), sha256Hex(wrapped.cachedBody))
    }
}
