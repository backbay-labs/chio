import Foundation

#if canImport(chio_kernel_mobile)
import chio_kernel_mobile
#else
public struct VerifiedCapability: Equatable, Sendable {
    public let id: String
    public let subjectHex: String
    public let issuerHex: String
    public let scopeJson: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
}

public struct PortablePassportMetadata: Equatable, Sendable {
    public let subject: String
    public let issuerHex: String
    public let issuedAt: UInt64
    public let expiresAt: UInt64
    public let evaluatedAt: UInt64
    public let payloadCanonicalHex: String
}
#endif

public enum ChioBindingError: Error, Equatable {
    case bindingUnavailable
}

public struct ChioKernel {
    public init() {}

    public func evaluate(requestJson: String) throws -> String {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.evaluate(requestJson: requestJson)
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func signReceipt(bodyJson: String, signingSeedHex: String) throws -> String {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.signReceipt(
            bodyJson: bodyJson,
            signingSeedHex: signingSeedHex
        )
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func verifyCapability(
        tokenJson: String,
        authorityPubHex: String
    ) throws -> VerifiedCapability {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.verifyCapability(
            tokenJson: tokenJson,
            authorityPubHex: authorityPubHex
        )
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func verifyPassport(
        envelopeJson: String,
        issuerPubHex: String,
        nowSecs: Int64
    ) throws -> PortablePassportMetadata {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.verifyPassport(
            envelopeJson: envelopeJson,
            issuerPubHex: issuerPubHex,
            nowSecs: nowSecs
        )
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func attestAppAttest(keyId: String, challengeHex: String) throws -> String {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.attestAppAttest(
            keyId: keyId,
            challengeHex: challengeHex
        )
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func attestPlayIntegrity(nonceHex: String) throws -> String {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.attestPlayIntegrity(nonceHex: nonceHex)
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }

    public func verifyMobileReceipt(
        receiptJson: String,
        evidenceJson: String
    ) throws -> String {
        #if canImport(chio_kernel_mobile)
        return try chio_kernel_mobile.verifyMobileReceipt(
            receiptJson: receiptJson,
            evidenceJson: evidenceJson
        )
        #else
        throw ChioBindingError.bindingUnavailable
        #endif
    }
}
