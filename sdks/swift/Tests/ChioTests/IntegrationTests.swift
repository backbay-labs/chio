import Foundation
import XCTest
@testable import Chio

final class IntegrationTests: XCTestCase {
    func testForwardToKernelFlowUsesSevenEntrySurface() async throws {
        let kernel = ChioKernel()
        XCTAssertThrowsError(
            try kernel.attestAppAttest(keyId: "mock-key", challengeHex: "010203")
        )
        XCTAssertThrowsError(
            try kernel.verifyMobileReceipt(receiptJson: "{}", evidenceJson: "{}")
        )
    }
}
