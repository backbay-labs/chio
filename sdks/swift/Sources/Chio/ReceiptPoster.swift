import Foundation

#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

public enum MobileReceiptErrorCode: String, Codable, Equatable {
    case receiptPostRejected = "urn:chio:error:mobile:receipt-post-rejected"
    case receiptSchemaInvalid = "urn:chio:error:mobile:receipt-schema-invalid"
    case oracleUnreachable = "urn:chio:error:mobile:oracle-unreachable"
}

public struct ReceiptPostResult: Equatable {
    public let receiptHash: String
    public let accepted: Bool
    public let statusCode: Int?
    public let errorCode: MobileReceiptErrorCode?
}

public final class ReceiptPoster {
    private let endpoint: URL
    private let session: URLSession
    private let maxAttempts: Int
    private let baseDelayNanoseconds: UInt64

    public init(
        endpoint: URL,
        session: URLSession = .shared,
        maxAttempts: Int = 4,
        baseDelayNanoseconds: UInt64 = 50_000_000
    ) {
        self.endpoint = endpoint
        self.session = session
        self.maxAttempts = max(1, maxAttempts)
        self.baseDelayNanoseconds = baseDelayNanoseconds
    }

    public func flush(queue: OfflineReceiptQueue) async -> [ReceiptPostResult] {
        let queued: [QueuedMobileReceipt]
        do {
            queued = try queue.oldestFirst()
        } catch {
            return [
                ReceiptPostResult(
                    receiptHash: "offline-queue",
                    accepted: false,
                    statusCode: nil,
                    errorCode: .oracleUnreachable
                ),
            ]
        }

        var results: [ReceiptPostResult] = []
        for receipt in queued {
            let result = await post(receipt)
            results.append(result)
            if result.accepted {
                try? queue.remove(tenantId: receipt.tenantId, receiptHash: receipt.receiptHash)
            } else {
                try? queue.markAttempt(receipt)
            }
        }
        return results
    }

    public func post(_ receipt: QueuedMobileReceipt) async -> ReceiptPostResult {
        for attempt in 1...maxAttempts {
            var request = URLRequest(url: endpoint)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = receipt.receiptJson.data(using: .utf8)

            do {
                let (_, response) = try await session.data(for: request)
                let statusCode = (response as? HTTPURLResponse)?.statusCode
                if let statusCode, (200..<300).contains(statusCode) {
                    return ReceiptPostResult(
                        receiptHash: receipt.receiptHash,
                        accepted: true,
                        statusCode: statusCode,
                        errorCode: nil
                    )
                }
                if statusCode == 400 || statusCode == 422 {
                    return rejected(receipt, statusCode: statusCode, code: .receiptSchemaInvalid)
                }
                if let statusCode, [401, 403, 409].contains(statusCode) {
                    return rejected(receipt, statusCode: statusCode, code: .receiptPostRejected)
                }
            } catch {
                if attempt == maxAttempts {
                    return rejected(receipt, statusCode: nil, code: .oracleUnreachable)
                }
            }

            if attempt < maxAttempts {
                let multiplier = UInt64(1 << UInt64(attempt - 1))
                try? await Task.sleep(nanoseconds: baseDelayNanoseconds * multiplier)
            }
        }

        return rejected(receipt, statusCode: nil, code: .oracleUnreachable)
    }

    private func rejected(
        _ receipt: QueuedMobileReceipt,
        statusCode: Int?,
        code: MobileReceiptErrorCode
    ) -> ReceiptPostResult {
        ReceiptPostResult(
            receiptHash: receipt.receiptHash,
            accepted: false,
            statusCode: statusCode,
            errorCode: code
        )
    }
}
