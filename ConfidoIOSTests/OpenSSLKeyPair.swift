//
//  DetachedKey.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation
@testable import ConfidoIOS


extension KeychainPrivateKey {
    //This extension makes it possible to extract the private key data. This is insecure, but only used for testing. This will not work on a device.
    public func keyData() throws ->  Data  {
        // It is possible that a key is not permanent, then there isn't any data to return
        var query : KeyChainPropertiesData = [ : ]

        let descriptor = keychainMatchPropertyValues()
        query[String(kSecClass)]            = kSecClassKey
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += descriptor.attributes

        let keyData: Data = try SecurityWrapper.secItemCopyMatching(query)
        return keyData
    }
}

@objc open class OpenSSLKeyPair : OpenSSLObject {
    @objc open fileprivate(set) var privateKeyData: Data
    @objc open fileprivate(set) var publicKeyData: Data
    open fileprivate(set) var keyLength: Int
    open fileprivate(set) var keyType: KeyType
    public init(keyLength: Int, keyType: KeyType, privateKeyData: Data, publicKeyData: Data) {
        self.privateKeyData = privateKeyData
        self.publicKeyData = publicKeyData
        self.keyType = keyType
        self.keyLength = keyLength
        super.init()
    }
    @objc open var publicKeyDataWithX509Header: Data {
        get {
            return publicKeyData.dataByPrependingX509RSAHeader()
        }
    }
    func publicKeyDataWithX590Header() -> Data? {
        return nil;
    }
}

@objc open class OpenSSLRSAKeyPair: OpenSSLKeyPair {
    @objc public init(keyLength: Int, privateKeyData: Data, publicKeyDataWithX509Header: Data) {
        let publicKeyData = publicKeyDataWithX509Header.dataByStrippingX509Header()
        super.init(keyLength: keyLength, keyType: .rsa, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }
    public init(keyLength: Int, privateKeyData: Data, publicKeyData: Data) {
        super.init(keyLength: keyLength, keyType: .rsa, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
    }

    override func publicKeyDataWithX590Header() -> Data? {
        return publicKeyData.dataByPrependingX509RSAHeader()
    }
}
