import CryptoKit
import DeviceCheck
import Foundation

public struct AppAttestKeyRecord: Equatable, Sendable {
    public let keyId: String
    public let createdAt: Date

    public init(keyId: String, createdAt: Date = Date()) {
        self.keyId = keyId
        self.createdAt = createdAt
    }
}

public struct AppAttestEvidence: Equatable, Sendable {
    public let keyId: String
    public let challengeHex: String
    public let attestationObjectBase64: String
    public let assertionObjectBase64: String?

    public init(
        keyId: String,
        challengeHex: String,
        attestationObjectBase64: String,
        assertionObjectBase64: String? = nil
    ) {
        self.keyId = keyId
        self.challengeHex = challengeHex
        self.attestationObjectBase64 = attestationObjectBase64
        self.assertionObjectBase64 = assertionObjectBase64
    }
}

public enum AppAttestClientError: Error, Equatable {
    case unsupported
    case emptyChallenge
}

public protocol AppAttestServicing: Sendable {
    var isSupported: Bool { get }
    func generateKey() async throws -> String
    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data
    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data
}

// `DCAppAttestService` is a thread-safe system service handle (the framework
// exposes it as a process-wide singleton); holding it in a `let` on a final
// class is safe to share across concurrency domains, so the Sendable
// conformance required by `AppAttestServicing` is unchecked rather than
// compiler-verified.
public final class DeviceCheckAppAttestService: AppAttestServicing, @unchecked Sendable {
    private let service: DCAppAttestService

    public init(service: DCAppAttestService = .shared) {
        self.service = service
    }

    public var isSupported: Bool {
        service.isSupported
    }

    public func generateKey() async throws -> String {
        try await withCheckedThrowingContinuation { continuation in
            service.generateKey { keyId, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let keyId else {
                    continuation.resume(throwing: AppAttestClientError.unsupported)
                    return
                }
                continuation.resume(returning: keyId)
            }
        }
    }

    public func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.attestKey(keyId, clientDataHash: clientDataHash) { attestation, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let attestation else {
                    continuation.resume(throwing: AppAttestClientError.unsupported)
                    return
                }
                continuation.resume(returning: attestation)
            }
        }
    }

    public func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            service.generateAssertion(keyId, clientDataHash: clientDataHash) { assertion, error in
                if let error {
                    continuation.resume(throwing: error)
                    return
                }
                guard let assertion else {
                    continuation.resume(throwing: AppAttestClientError.unsupported)
                    return
                }
                continuation.resume(returning: assertion)
            }
        }
    }
}

public final class AppAttestClient: Sendable {
    private let service: AppAttestServicing

    public init(service: AppAttestServicing = DeviceCheckAppAttestService()) {
        self.service = service
    }

    public func createKey() async throws -> AppAttestKeyRecord {
        guard service.isSupported else {
            throw AppAttestClientError.unsupported
        }
        return AppAttestKeyRecord(keyId: try await service.generateKey())
    }

    public func attestKey(keyId: String, challenge: Data) async throws -> AppAttestEvidence {
        guard !challenge.isEmpty else {
            throw AppAttestClientError.emptyChallenge
        }
        let challengeHash = Self.hash(challenge)
        let attestation = try await service.attestKey(keyId, clientDataHash: challengeHash)
        return AppAttestEvidence(
            keyId: keyId,
            challengeHex: challenge.hexEncodedString(),
            attestationObjectBase64: attestation.base64EncodedString()
        )
    }

    public func generateAssertion(keyId: String, challenge: Data) async throws -> AppAttestEvidence {
        guard !challenge.isEmpty else {
            throw AppAttestClientError.emptyChallenge
        }
        let challengeHash = Self.hash(challenge)
        let assertion = try await service.generateAssertion(keyId, clientDataHash: challengeHash)
        return AppAttestEvidence(
            keyId: keyId,
            challengeHex: challenge.hexEncodedString(),
            attestationObjectBase64: "",
            assertionObjectBase64: assertion.base64EncodedString()
        )
    }

    public static func hash(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }
}

extension Data {
    fileprivate func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
