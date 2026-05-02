package dev.chio

import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

class ChioBindingUnavailable(method: String) :
    CodedException("Chio mobile binding unavailable for $method")

class ChioModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("Chio")

        AsyncFunction("evaluate") { requestJson: String ->
            throw ChioBindingUnavailable("evaluate")
        }

        AsyncFunction("signReceipt") { bodyJson: String, signingSeedHex: String ->
            throw ChioBindingUnavailable("signReceipt")
        }

        AsyncFunction("verifyCapability") { tokenJson: String, authorityPubHex: String ->
            throw ChioBindingUnavailable("verifyCapability")
        }

        AsyncFunction("verifyPassport") { envelopeJson: String, issuerPubHex: String, nowSecs: Double ->
            throw ChioBindingUnavailable("verifyPassport")
        }

        AsyncFunction("attestAppAttest") { keyId: String, challengeHex: String ->
            throw ChioBindingUnavailable("attestAppAttest")
        }

        AsyncFunction("attestPlayIntegrity") { nonceHex: String ->
            throw ChioBindingUnavailable("attestPlayIntegrity")
        }

        AsyncFunction("verifyMobileReceipt") { receiptJson: String, evidenceJson: String ->
            throw ChioBindingUnavailable("verifyMobileReceipt")
        }
    }
}
