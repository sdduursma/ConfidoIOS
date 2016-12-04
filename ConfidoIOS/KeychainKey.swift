//
//  KeychainKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//
//

import Foundation
import CommonCrypto


extension SecIdentity {
    func certificateRef() throws -> SecCertificate {
        var certificateRef: SecCertificate? = nil
        try ensureOK(SecIdentityCopyCertificate(self, &certificateRef))
        return certificateRef!
    }

    func privateKeyRef() throws -> SecKey {
        var keyRef: SecKey? = nil
        try ensureOK(SecIdentityCopyPrivateKey(self, &keyRef))
        return keyRef!
    }
}


open class KeychainKey : KeychainItem, KeychainKeyClassProperties {
    open class func keychainKeyFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainKey {
        let keyClass = KeyClass.keyClass(attributes[String(kSecAttrKeyClass)])
        switch keyClass {
        case .privateKey: return try KeychainPrivateKey(SecItemAttributes: attributes)
        case .publicKey:  return try KeychainPublicKey(SecItemAttributes: attributes)
        default:          return try KeychainKey(SecItemAttributes: attributes)
        }
    }

    var keySecKey: SecKey?

    public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        keySecKey = keyRef
        super.init(securityClass: .key,  byCopyingAttributes: descriptor)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.key, SecItemAttributes: attributes)
        self.keySecKey = try KeychainKey.getKeySecKey(SecItemAttributes: attributes as NSDictionary)
    }

    class func getKeySecKey(SecItemAttributes attributes: NSDictionary) throws -> SecKey {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecKeyGetTypeID() {
                return (valueRef as! SecKey)
            } else if CFGetTypeID(valueRef) == SecIdentityGetTypeID() {
                let secIdentity = (valueRef as! SecIdentity)
                return try secIdentity.privateKeyRef()
            }
        }
        fatalError("No SecKey Reference")
    }

    override open func specifierMatchingProperties() -> Set<String> {
       return kKeyItemMatchingProperties
    }

    func ensureRSAOrECKey() throws {
        if (self.keyType == KeyType.rsa) { return }
        if (self.keyType == KeyType.elypticCurve) { return }

        throw KeychainError.unimplementedKeyType(reason: "Not implemented for key types other than RSA or EC")
    }
}

/**
An instance of an IOS Keychain Public Key
*/
open class KeychainSymmetricKey : KeychainKey, KeychainFindable, GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainSymmetricKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.symmetricKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.symmetricKey)
    }
    open func withKeyDataDo(_ closure : (Data)-> Void ) throws {
        // this key's keyData is cryptographic key material and should not be passed around or stored.
        // Use this very carefully
        let keyData = try fetchKeyData(self)
        closure(keyData)
    }
}

func fetchKeyData(_ key: KeychainKey) throws -> Data {
    var query : KeyChainPropertiesData = [ : ]

    let descriptor = key.keychainMatchPropertyValues()
    query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
    query[String(kSecReturnData)]       = kCFBooleanTrue
    query[String(kSecMatchLimit)]       = kSecMatchLimitOne
    query += descriptor.keychainMatchPropertyValues()

    let keyData: Data = try SecurityWrapper.secItemCopyMatching(query)
    return keyData

}


extension KeychainSymmetricKey {
}
