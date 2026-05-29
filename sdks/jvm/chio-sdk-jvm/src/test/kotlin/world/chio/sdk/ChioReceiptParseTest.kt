package world.chio.sdk

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.fasterxml.jackson.module.kotlin.readValue
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ChioReceiptParseTest {
    private val mapper = jacksonObjectMapper()

    @Test
    fun `parses canonical allow receipt`() {
        val json =
            """
            {
              "id": "r-1",
              "timestamp": 1700000000,
              "capability_id": "cap-1",
              "tool_server": "server",
              "tool_name": "events:consume:topic",
              "action": {"parameters": {"a": 1}, "parameter_hash": "abc"},
              "decision": {"verdict": "allow"},
              "receipt_kind": "mediated_decision",
              "boundary_class": "prevent",
              "trust_level": "mediated",
              "content_hash": "c",
              "policy_hash": "p",
              "evidence": [],
              "kernel_key": "k",
              "signature": "s"
            }
            """.trimIndent()
        val r: ChioReceipt = mapper.readValue(json)
        assertEquals("r-1", r.id)
        assertTrue(r.isAllowed())
        assertFalse(r.isDenied())
        assertTrue(r.evidence.isEmpty())
        assertNull(r.metadata)
    }

    @Test
    fun `parses deny receipt with metadata`() {
        val json =
            """
            {
              "id": "r-2",
              "timestamp": 1700000000,
              "capability_id": "cap",
              "tool_server": "s",
              "tool_name": "t",
              "action": {"parameters": {}, "parameter_hash": "h"},
              "decision": {"verdict": "deny", "reason": "blocked", "guard": "G"},
              "content_hash": "h",
              "policy_hash": "",
              "evidence": [],
              "metadata": {"a": null, "b": 1},
              "kernel_key": "",
              "signature": ""
            }
            """.trimIndent()
        val r: ChioReceipt = mapper.readValue(json)
        assertTrue(r.isDenied())
        assertEquals("blocked", r.decision?.reason)
        assertEquals("G", r.decision?.guard)
        // Null map values preserved on parse.
        val meta = r.metadata!!
        assertTrue(meta.containsKey("a"))
        assertNull(meta["a"])
        assertEquals(1, meta["b"])
    }
}
