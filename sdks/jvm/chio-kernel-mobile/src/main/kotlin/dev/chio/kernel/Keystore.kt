package dev.chio.kernel

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore

data class AndroidKeystoreKey(
    val alias: String,
    val trustLevel: TrustLevel,
    val keyPair: KeyPair,
)

class AndroidKeystore {
    private val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    fun generateSigningKey(alias: String, preferStrongBox: Boolean = true): AndroidKeystoreKey {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            "AndroidKeyStore",
        )
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .setAttestationChallenge(alias.toByteArray(Charsets.UTF_8))

        val strongBoxRequested = preferStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P
        if (strongBoxRequested) {
            builder.setIsStrongBoxBacked(true)
        }

        return try {
            generator.initialize(builder.build())
            AndroidKeystoreKey(
                alias = alias,
                trustLevel = if (strongBoxRequested) TrustLevel.HARDWARE else TrustLevel.SOFTWARE,
                keyPair = generator.generateKeyPair(),
            )
        } catch (error: Exception) {
            if (!strongBoxRequested) {
                throw error
            }
            val fallback = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .setAttestationChallenge(alias.toByteArray(Charsets.UTF_8))
                .build()
            generator.initialize(fallback)
            AndroidKeystoreKey(
                alias = alias,
                trustLevel = TrustLevel.SOFTWARE,
                keyPair = generator.generateKeyPair(),
            )
        }
    }

    fun contains(alias: String): Boolean = keyStore.containsAlias(alias)
}
