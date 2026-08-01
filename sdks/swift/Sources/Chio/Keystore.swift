import Foundation
import Security

public enum ChioKeystoreError: Error, Equatable {
    case accessControlUnavailable
    case secureEnclaveUnavailable(OSStatus)
    case keyCreationFailed(OSStatus)
}

public struct SecureEnclaveKeyDescriptor: Equatable, Sendable {
    public let tag: String
    public let accessGroup: String?

    public init(tag: String, accessGroup: String? = nil) {
        self.tag = tag
        self.accessGroup = accessGroup
    }
}

public final class SecureEnclaveKeystore: Sendable {
    public init() {}

    public func createSigningKey(
        descriptor: SecureEnclaveKeyDescriptor
    ) throws -> SecKey {
        var accessControlError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage],
            &accessControlError
        ) else {
            throw ChioKeystoreError.accessControlUnavailable
        }

        var privateKeyAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: Data(descriptor.tag.utf8),
            kSecAttrAccessControl as String: access
        ]
        if let accessGroup = descriptor.accessGroup {
            privateKeyAttributes[kSecAttrAccessGroup as String] = accessGroup
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateKeyAttributes
        ]

        var keyError: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
            let status = keyError == nil ? errSecUnimplemented : errSecParam
            throw ChioKeystoreError.keyCreationFailed(status)
        }
        return key
    }

    public func loadSigningKey(
        descriptor: SecureEnclaveKeyDescriptor
    ) throws -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(descriptor.tag.utf8),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true
        ]
        if let accessGroup = descriptor.accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw ChioKeystoreError.secureEnclaveUnavailable(status)
        }
        // CFTypeRef cannot be conditionally downcast to a CoreFoundation type;
        // verify the returned ref really is a key before the unconditional bridge.
        guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
            throw ChioKeystoreError.secureEnclaveUnavailable(errSecDecode)
        }
        return (item as! SecKey)
    }
}
