package world.chio

import jakarta.servlet.ReadListener
import jakarta.servlet.ServletInputStream
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import java.io.BufferedReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.nio.charset.Charset

/**
 * Request wrapper that caches the full body so Chio can hash it without
 * consuming the stream seen by downstream filters and controllers.
 */
class CachedBodyHttpServletRequest(
    request: HttpServletRequest,
) : HttpServletRequestWrapper(request) {
    val cachedBody: ByteArray = request.inputStream.readAllBytes()

    override fun getInputStream(): ServletInputStream {
        val delegate = ByteArrayInputStream(cachedBody)
        return object : ServletInputStream() {
            override fun isFinished(): Boolean = delegate.available() == 0

            override fun isReady(): Boolean = true

            override fun setReadListener(readListener: ReadListener?) {
                if (readListener != null) {
                    try {
                        readListener.onDataAvailable()
                        if (isFinished) {
                            readListener.onAllDataRead()
                        }
                    } catch (error: Exception) {
                        readListener.onError(error)
                    }
                }
            }

            override fun read(): Int = delegate.read()
        }
    }

    override fun getReader(): BufferedReader {
        val charset = characterEncoding?.let(Charset::forName) ?: Charsets.UTF_8
        return BufferedReader(InputStreamReader(inputStream, charset))
    }
}
