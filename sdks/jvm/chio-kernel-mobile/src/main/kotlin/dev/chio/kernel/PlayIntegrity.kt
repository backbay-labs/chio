package dev.chio.kernel

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManager
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

data class PlayIntegrityEvidence(
    val token: String,
    val nonce: String,
)

class PlayIntegrityClient(
    private val integrityManager: IntegrityManager,
) {
    constructor(context: Context) : this(IntegrityManagerFactory.create(context))

    suspend fun requestStandardVerdict(nonce: String): PlayIntegrityEvidence {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        val response = suspendCancellableCoroutine { continuation ->
            integrityManager.requestIntegrityToken(request)
                .addOnSuccessListener { continuation.resume(it.token()) }
                .addOnFailureListener { continuation.resumeWithException(it) }
        }
        return PlayIntegrityEvidence(token = response, nonce = nonce)
    }
}
