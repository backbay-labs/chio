import Foundation

#if canImport(Security)
import Security
#endif

public struct QueuedMobileReceipt: Codable, Equatable {
    public let tenantId: String
    public let receiptHash: String
    public let receiptJson: String
    public let enqueuedAtUnixMillis: Int64
    public let attemptCount: Int

    public init(
        tenantId: String,
        receiptHash: String,
        receiptJson: String,
        enqueuedAtUnixMillis: Int64,
        attemptCount: Int = 0
    ) {
        self.tenantId = tenantId
        self.receiptHash = receiptHash
        self.receiptJson = receiptJson
        self.enqueuedAtUnixMillis = enqueuedAtUnixMillis
        self.attemptCount = attemptCount
    }

    public var accountKey: String {
        "\(tenantId)|\(receiptHash)"
    }

    public func incrementedAttempt() -> QueuedMobileReceipt {
        QueuedMobileReceipt(
            tenantId: tenantId,
            receiptHash: receiptHash,
            receiptJson: receiptJson,
            enqueuedAtUnixMillis: enqueuedAtUnixMillis,
            attemptCount: attemptCount + 1
        )
    }
}

public enum OfflineQueueError: Error, Equatable {
    case keychainUnavailable
    case keychainStatus(Int32)
    case invalidReceiptKey
    case decodeFailed(String)
}

private struct QueueIndex: Codable {
    var keys: [String]
}

public final class OfflineReceiptQueue {
    private let service: String
    private let maxDepth: Int
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    public init(service: String = "dev.chio.mobile.receipts", maxDepth: Int = 256) {
        self.service = service
        self.maxDepth = max(1, maxDepth)
    }

    public func enqueue(_ receipt: QueuedMobileReceipt) throws {
        #if canImport(Security)
        guard !receipt.tenantId.isEmpty, !receipt.receiptHash.isEmpty else {
            throw OfflineQueueError.invalidReceiptKey
        }

        var index = try loadIndex()
        index.keys.removeAll { $0 == receipt.accountKey }
        index.keys.append(receipt.accountKey)
        while index.keys.count > maxDepth {
            let dropped = index.keys.removeFirst()
            try deleteAccount(dropped)
        }

        try storeData(try encoder.encode(receipt), account: receipt.accountKey)
        try storeIndex(index)
        #else
        throw OfflineQueueError.keychainUnavailable
        #endif
    }

    public func oldestFirst() throws -> [QueuedMobileReceipt] {
        #if canImport(Security)
        let index = try loadIndex()
        let receipts = try index.keys.compactMap { key -> QueuedMobileReceipt? in
            guard let data = try loadData(account: key) else {
                return nil
            }
            return try decoder.decode(QueuedMobileReceipt.self, from: data)
        }
        return receipts.sorted { lhs, rhs in
            lhs.enqueuedAtUnixMillis < rhs.enqueuedAtUnixMillis
        }
        #else
        throw OfflineQueueError.keychainUnavailable
        #endif
    }

    public func markAttempt(_ receipt: QueuedMobileReceipt) throws {
        #if canImport(Security)
        try storeData(try encoder.encode(receipt.incrementedAttempt()), account: receipt.accountKey)
        #else
        throw OfflineQueueError.keychainUnavailable
        #endif
    }

    public func remove(tenantId: String, receiptHash: String) throws {
        #if canImport(Security)
        let account = "\(tenantId)|\(receiptHash)"
        try deleteAccount(account)
        var index = try loadIndex()
        index.keys.removeAll { $0 == account }
        try storeIndex(index)
        #else
        throw OfflineQueueError.keychainUnavailable
        #endif
    }

    #if canImport(Security)
    private var indexAccount: String {
        "__chio_mobile_receipt_index__"
    }

    private func keychainQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func loadIndex() throws -> QueueIndex {
        guard let data = try loadData(account: indexAccount) else {
            return QueueIndex(keys: [])
        }
        do {
            return try decoder.decode(QueueIndex.self, from: data)
        } catch {
            throw OfflineQueueError.decodeFailed("offline queue index: \(error)")
        }
    }

    private func storeIndex(_ index: QueueIndex) throws {
        try storeData(try encoder.encode(index), account: indexAccount)
    }

    private func loadData(account: String) throws -> Data? {
        var query = keychainQuery(account: account)
        query[kSecReturnData as String] = kCFBooleanTrue
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw OfflineQueueError.keychainStatus(Int32(status))
        }
        guard let data = result as? Data else {
            throw OfflineQueueError.decodeFailed("offline queue item was not data")
        }
        return data
    }

    private func storeData(_ data: Data, account: String) throws {
        try deleteAccount(account, ignoreMissing: true)
        var query = keychainQuery(account: account)
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw OfflineQueueError.keychainStatus(Int32(status))
        }
    }

    private func deleteAccount(_ account: String, ignoreMissing: Bool = false) throws {
        let status = SecItemDelete(keychainQuery(account: account) as CFDictionary)
        if ignoreMissing, status == errSecItemNotFound {
            return
        }
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw OfflineQueueError.keychainStatus(Int32(status))
        }
    }
    #endif
}
