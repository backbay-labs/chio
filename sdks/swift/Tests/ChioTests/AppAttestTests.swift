import Foundation
import XCTest
@testable import Chio

private final class MockAppAttestService: AppAttestServicing {
    let isSupported: Bool
    let keyId: String
    let attestation: Data
    let assertion: Data

    init(
        isSupported: Bool = true,
        keyId: String = "mock-key",
        attestation: Data = Data([0xA1, 0x01, 0x02]),
        assertion: Data = Data([0xA1, 0x03, 0x04])
    ) {
        self.isSupported = isSupported
        self.keyId = keyId
        self.attestation = attestation
        self.assertion = assertion
    }

    func generateKey() async throws -> String {
        keyId
    }

    func attestKey(_ keyId: String, clientDataHash: Data) async throws -> Data {
        XCTAssertFalse(clientDataHash.isEmpty)
        return attestation
    }

    func generateAssertion(_ keyId: String, clientDataHash: Data) async throws -> Data {
        XCTAssertFalse(clientDataHash.isEmpty)
        return assertion
    }
}

final class AppAttestTests: XCTestCase {
    func testGenerateKeyAndAttestationEnvelope() async throws {
        let client = AppAttestClient(service: MockAppAttestService())
        let key = try await client.createKey()
        XCTAssertEqual(key.keyId, "mock-key")

        let evidence = try await client.attestKey(
            keyId: key.keyId,
            challenge: Data([0x01, 0x02, 0x03])
        )
        XCTAssertEqual(evidence.keyId, "mock-key")
        XCTAssertEqual(evidence.challengeHex, "010203")
        XCTAssertEqual(evidence.attestationObjectBase64, Data([0xA1, 0x01, 0x02]).base64EncodedString())
    }

    func testGenerateAssertionBindsChallengeHash() async throws {
        let client = AppAttestClient(service: MockAppAttestService())
        let evidence = try await client.generateAssertion(
            keyId: "mock-key",
            challenge: Data([0x04, 0x05])
        )
        XCTAssertEqual(evidence.assertionObjectBase64, Data([0xA1, 0x03, 0x04]).base64EncodedString())
    }
}
