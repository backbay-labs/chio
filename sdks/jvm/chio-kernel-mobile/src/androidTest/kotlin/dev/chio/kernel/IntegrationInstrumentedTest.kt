package dev.chio.kernel

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class IntegrationInstrumentedTest {
    @Test
    fun forwardToKernelEvidenceShapeUsesAndroidPlatform() {
        val evidence = ChioMobileReceiptEvidence(
            schema = "chio.mobile.attestation-evidence.v1",
            platform = "play_integrity",
            token = "token",
            nonce = "nonce",
            trustLevel = TrustLevel.HARDWARE,
        )
        assertEquals("play_integrity", evidence.platform)
    }
}
