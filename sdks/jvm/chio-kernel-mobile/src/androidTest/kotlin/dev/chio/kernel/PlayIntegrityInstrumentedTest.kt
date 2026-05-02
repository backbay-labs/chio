package dev.chio.kernel

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PlayIntegrityInstrumentedTest {
    @Test
    fun evidenceCarriesNonce() {
        val evidence = PlayIntegrityEvidence(token = "test-token", nonce = "issuer-nonce")
        assertEquals("issuer-nonce", evidence.nonce)
    }
}
