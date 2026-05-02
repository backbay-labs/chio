package dev.chio.kernel

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import kotlin.math.max

enum class MobileReceiptErrorCode(val urn: String) {
    RECEIPT_POST_REJECTED("urn:chio:error:mobile:receipt-post-rejected"),
    RECEIPT_SCHEMA_INVALID("urn:chio:error:mobile:receipt-schema-invalid"),
    ORACLE_UNREACHABLE("urn:chio:error:mobile:oracle-unreachable"),
}

data class ReceiptPostResult(
    val receiptHash: String,
    val accepted: Boolean,
    val statusCode: Int?,
    val errorCode: MobileReceiptErrorCode?,
)

class ReceiptPoster(
    private val endpoint: URL,
    private val maxAttempts: Int = 4,
    private val baseDelayMillis: Long = 50,
) {
    fun flush(queue: OfflineReceiptQueue): List<ReceiptPostResult> =
        queue.oldestFirst().map { receipt ->
            val result = post(receipt)
            if (result.accepted) {
                queue.remove(receipt.tenantId, receipt.receiptHash)
            } else {
                queue.markAttempt(receipt)
            }
            result
        }

    fun post(receipt: QueuedMobileReceipt): ReceiptPostResult {
        val attempts = max(1, maxAttempts)
        for (attempt in 1..attempts) {
            try {
                val status = postOnce(receipt)
                if (status in 200..299) {
                    return accepted(receipt, status)
                }
                if (status == 400 || status == 422) {
                    return rejected(receipt, status, MobileReceiptErrorCode.RECEIPT_SCHEMA_INVALID)
                }
                if (status == 401 || status == 403 || status == 409) {
                    return rejected(receipt, status, MobileReceiptErrorCode.RECEIPT_POST_REJECTED)
                }
            } catch (_: IOException) {
                if (attempt == attempts) {
                    return rejected(receipt, null, MobileReceiptErrorCode.ORACLE_UNREACHABLE)
                }
            }

            if (attempt < attempts) {
                Thread.sleep(baseDelayMillis * (1L shl (attempt - 1)))
            }
        }
        return rejected(receipt, null, MobileReceiptErrorCode.ORACLE_UNREACHABLE)
    }

    private fun postOnce(receipt: QueuedMobileReceipt): Int {
        val connection = endpoint.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.setRequestProperty("Content-Type", "application/json")
        connection.outputStream.use { output ->
            output.write(receipt.receiptJson.toByteArray(Charsets.UTF_8))
        }
        return connection.responseCode
    }

    private fun accepted(receipt: QueuedMobileReceipt, statusCode: Int): ReceiptPostResult =
        ReceiptPostResult(
            receiptHash = receipt.receiptHash,
            accepted = true,
            statusCode = statusCode,
            errorCode = null,
        )

    private fun rejected(
        receipt: QueuedMobileReceipt,
        statusCode: Int?,
        code: MobileReceiptErrorCode,
    ): ReceiptPostResult =
        ReceiptPostResult(
            receiptHash = receipt.receiptHash,
            accepted = false,
            statusCode = statusCode,
            errorCode = code,
        )
}
