//
//  PublicPrivateKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 25/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//




import Foundation
import Security


public protocol Key {

}

public protocol PublicKey : Key {

}


extension PublicKey where Self : PublicKey {

}


public protocol PrivateKey : Key {

}

extension PublicKey where Self : PublicKey {

}

/**
An instance of an IOS Keychain Public Key
*/
public class KeychainPublicKey : KeychainKey, PublicKey, KeychainFindable, InjectKeychainFind {
    public typealias QueryType = KeychainKeyProperties
    public typealias ResultType = KeychainPublicKey

    override public init(properties: KeychainKeyProperties, keyRef: SecKey) {
        super.init(properties: properties, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) {
        super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }
}


/**
An instance of an IOS Keychain Private Key
*/
public class KeychainPrivateKey : KeychainKey, PrivateKey, KeychainFindable,  InjectKeychainFind {
    public typealias QueryType = KeychainKeyProperties
    public typealias ResultType = KeychainPrivateKey

    override public init(properties: KeychainKeyProperties, keyRef: SecKey) {
        super.init(properties: properties, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) {
        super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }
}

public protocol KeyPair {
    typealias PrivKeyType : PrivateKey
    typealias PubKeyType  : PublicKey
    var privateKey: PrivKeyType { get }
    var publicKey: PubKeyType  { get }
    init (publicKey: PubKeyType, privateKey: PrivKeyType)
}


extension KeyPair {
}

/**
An instance of an IOS Keypair
*/

public class KeychainKeyPair : KeychainItem, KeyPair, KeychainFindable {
    public let privateKey: KeychainPrivateKey
    public let publicKey:  KeychainPublicKey


    public class func importKeyPair(pemEncodedData keyData: NSData, encryptedWithPassphrase passphrase: String, keyLabel: String? = nil , keyAppTag: String? = nil, keyAppLabel: String? = nil) throws -> DetachedKeyPair {
        let openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyData, encryptedWithPassword: passphrase)
        return DetachedKeyPair(openSSLKeypair: openSSLKeyPair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public class func findInKeychain(matchingProperties: KeychainKeyPairProperties) throws -> KeychainKeyPair? {
        let privateKey = try KeychainPrivateKey.findInKeychain(matchingProperties.privateKeyQueryProperties() as KeychainPrivateKey.QueryType)
        let publicKey = try KeychainPublicKey.findInKeychain(matchingProperties.publicKeyQueryProperties())
        if let privateKey = privateKey, let publicKey = publicKey {
            return KeychainKeyPair(publicKey: publicKey as KeychainPublicKey, privateKey: privateKey as KeychainPrivateKey)

        }
        return nil
    }


    public init(properties: KeychainKeyPairProperties, publicKeyRef: SecKey, privateKeyRef: SecKey) {
        self.privateKey = KeychainPrivateKey(properties: properties, keyRef: privateKeyRef)
        self.publicKey  = KeychainPublicKey(properties: properties, keyRef: publicKeyRef)
        super.init(securityClass: SecurityClass.Key)
    }

    public required init (publicKey: KeychainPublicKey, privateKey: KeychainPrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: SecurityClass.Key)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) {
        self.privateKey = KeychainPrivateKey(SecItemAttributes: attributes)
        self.publicKey  = KeychainPublicKey(SecItemAttributes: attributes)
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)
    }

    public func certificateSigningRequest(attributes: [ String : String]) -> NSData? {
        if let openSSLKeyPair = self.openSSLKeyPair {
            do {
                return try OpenSSL.generateCSRWithKeyPair(openSSLKeyPair, csrData: attributes)
            } catch _ {
                return nil
            }
        }
        return nil
    }

    public lazy var openSSLKeyPair : OpenSSLKeyPair? = {
        
        if self.privateKey.keyType == .RSA,
            let privateKeyData = self.privateKey.keyData, let publicKeyData = self.publicKey.keyData {
            return OpenSSLRSAKeyPair(keyLength: self.publicKey.keySize, privateKeyData: privateKeyData, publicKeyData: publicKeyData)
        }
        return nil;
    }()
}

public class DetachedPrivateKey : KeychainKeyProperties, SecItemAddable {
    init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String?, keyAppTag: String?, keyAppLabel: String?) {
        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: .PrivateKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        attributes[String(kSecValueData)] = keypair.privateKeyData

    }
}

public class DetachedPublicKey : KeychainKeyProperties, SecItemAddable {
    init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String?, keyAppTag: String?, keyAppLabel: String?) {
        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: .PublicKey, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        attributes[String(kSecValueData)] = keypair.publicKeyData
    }

}

public class DetachedKeyPair :KeychainKeyPairProperties,  KeychainAddable {
    //Marks that this class maps to KeychainKeyPair when matching
    public typealias KeychainClassType = KeychainKeyPair
//    public typealias QueryType = KeychainKeyPairQueryProperties
//    public typealias ResultType = KeychainKeyPair

    let openSSLKeyPair: OpenSSLKeyPair
    let privateKey : DetachedPrivateKey
    let publicKey  : DetachedPublicKey
    public init(openSSLKeypair keypair: OpenSSLKeyPair, keyLabel: String? , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        self.openSSLKeyPair = keypair
        self.privateKey = DetachedPrivateKey(openSSLKeypair: keypair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
        self.publicKey = DetachedPublicKey(openSSLKeypair: keypair, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)

        super.init(keyType: keypair.keyType, keySize: keypair.keyLength, keyClass: nil, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func addToKeychain() throws -> KeychainKeyPair? {
        try privateKey.addToKeychain()
        try publicKey.addToKeychain()

        return try KeychainKeyPair.findInKeychain(self)
    }
}




