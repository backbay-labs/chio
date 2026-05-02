import ExpoModulesCore
import Foundation

struct ChioBindingUnavailable: Error {
    let method: String
}

public class Chio: Module {
    public func definition() -> ModuleDefinition {
        Name("Chio")

        AsyncFunction("evaluate") { (_ requestJson: String) -> String in
            try unavailable("evaluate")
        }

        AsyncFunction("signReceipt") { (_ bodyJson: String, _ signingSeedHex: String) -> String in
            try unavailable("signReceipt")
        }

        AsyncFunction("verifyCapability") { (_ tokenJson: String, _ authorityPubHex: String) -> [String: Any] in
            try unavailable("verifyCapability")
        }

        AsyncFunction("verifyPassport") { (_ envelopeJson: String, _ issuerPubHex: String, _ nowSecs: Int64) -> [String: Any] in
            try unavailable("verifyPassport")
        }

        AsyncFunction("attestAppAttest") { (_ keyId: String, _ challengeHex: String) -> String in
            try unavailable("attestAppAttest")
        }

        AsyncFunction("attestPlayIntegrity") { (_ nonceHex: String) -> String in
            try unavailable("attestPlayIntegrity")
        }

        AsyncFunction("verifyMobileReceipt") { (_ receiptJson: String, _ evidenceJson: String) -> String in
            try unavailable("verifyMobileReceipt")
        }
    }
}

private func unavailable<T>(_ method: String) throws -> T {
    throw ChioBindingUnavailable(method: method)
}
