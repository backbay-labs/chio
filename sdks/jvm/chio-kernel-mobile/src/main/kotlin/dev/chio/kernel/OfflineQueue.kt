package dev.chio.kernel

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import org.json.JSONArray
import org.json.JSONObject

data class QueuedMobileReceipt(
    val tenantId: String,
    val receiptHash: String,
    val receiptJson: String,
    val enqueuedAtUnixMillis: Long,
    val attemptCount: Int = 0,
) {
    val accountKey: String = "$tenantId|$receiptHash"

    fun incrementedAttempt(): QueuedMobileReceipt = copy(attemptCount = attemptCount + 1)
}

class OfflineReceiptQueue private constructor(
    private val preferences: SharedPreferences,
    private val maxDepth: Int,
) {
    companion object {
        private const val INDEX_KEY = "__chio_mobile_receipt_index__"

        fun encrypted(
            context: Context,
            name: String = "chio-mobile-receipts",
            maxDepth: Int = 256,
        ): OfflineReceiptQueue {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            val preferences = EncryptedSharedPreferences.create(
                context,
                name,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
            return OfflineReceiptQueue(preferences, maxDepth.coerceAtLeast(1))
        }
    }

    @Synchronized
    fun enqueue(receipt: QueuedMobileReceipt) {
        require(receipt.tenantId.isNotBlank()) { "tenantId must not be blank" }
        require(receipt.receiptHash.isNotBlank()) { "receiptHash must not be blank" }

        val keys = loadIndex().filterNot { it == receipt.accountKey }.toMutableList()
        keys.add(receipt.accountKey)
        while (keys.size > maxDepth) {
            val dropped = keys.removeAt(0)
            preferences.edit().remove(dropped).apply()
        }

        preferences.edit()
            .putString(receipt.accountKey, encode(receipt).toString())
            .putString(INDEX_KEY, JSONArray(keys).toString())
            .apply()
    }

    @Synchronized
    fun oldestFirst(): List<QueuedMobileReceipt> =
        loadIndex()
            .mapNotNull { key -> preferences.getString(key, null)?.let(::decode) }
            .sortedBy { it.enqueuedAtUnixMillis }

    @Synchronized
    fun markAttempt(receipt: QueuedMobileReceipt) {
        preferences.edit()
            .putString(receipt.accountKey, encode(receipt.incrementedAttempt()).toString())
            .apply()
    }

    @Synchronized
    fun remove(tenantId: String, receiptHash: String) {
        val account = "$tenantId|$receiptHash"
        val keys = loadIndex().filterNot { it == account }
        preferences.edit()
            .remove(account)
            .putString(INDEX_KEY, JSONArray(keys).toString())
            .apply()
    }

    private fun loadIndex(): List<String> {
        val raw = preferences.getString(INDEX_KEY, null) ?: return emptyList()
        val array = JSONArray(raw)
        return (0 until array.length()).map { index -> array.getString(index) }
    }

    private fun encode(receipt: QueuedMobileReceipt): JSONObject =
        JSONObject()
            .put("tenantId", receipt.tenantId)
            .put("receiptHash", receipt.receiptHash)
            .put("receiptJson", receipt.receiptJson)
            .put("enqueuedAtUnixMillis", receipt.enqueuedAtUnixMillis)
            .put("attemptCount", receipt.attemptCount)

    private fun decode(raw: String): QueuedMobileReceipt {
        val json = JSONObject(raw)
        return QueuedMobileReceipt(
            tenantId = json.getString("tenantId"),
            receiptHash = json.getString("receiptHash"),
            receiptJson = json.getString("receiptJson"),
            enqueuedAtUnixMillis = json.getLong("enqueuedAtUnixMillis"),
            attemptCount = json.optInt("attemptCount", 0),
        )
    }
}
