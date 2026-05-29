/**
 * Receipt / DLQ side-output tag constants. Names MUST be wire-stable.
 * Mirrors RECEIPT_TAG_NAME / DLQ_TAG_NAME in chio_streaming/flink.py.
 *
 * Factory methods are lazy because OutputTag<ByteArray> requires the
 * Flink classpath (compileOnly dependency); call them only from
 * operator code that runs after open() completes.
 */
package world.chio.flink

import org.apache.flink.api.common.typeinfo.TypeInformation
import org.apache.flink.streaming.api.datastream.DataStream
import org.apache.flink.util.OutputTag

object ChioOutputTags {
    const val RECEIPT_TAG_NAME: String = "chio-receipt"
    const val DLQ_TAG_NAME: String = "chio-dlq"

    @JvmStatic
    fun receiptTag(): OutputTag<ByteArray> = OutputTag(RECEIPT_TAG_NAME, TypeInformation.of(ByteArray::class.java))

    @JvmStatic
    fun dlqTag(): OutputTag<ByteArray> = OutputTag(DLQ_TAG_NAME, TypeInformation.of(ByteArray::class.java))

    @Suppress("unused")
    private val dataStreamClass: Class<DataStream<*>> = DataStream::class.java
}
