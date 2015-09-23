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
public class KeychainPublicKey : KeychainKey, PublicKey, KeychainFindable, GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPublicKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
    }
    public lazy var keyData: NSData? = {
        // It is possible that a key is not permanent, then there isn't any data to return
        do {
            return try Keychain.keyData(self)
        }
        catch let error {
            //TODO: Fix
            print("error \(error)")
            return nil
        }
        }()
}


/**
An instance of an IOS Keychain Private Key
*/
public class KeychainPrivateKey : KeychainKey, PrivateKey, KeychainFindable,  GenerateKeychainFind {
    //This specifies the argument type and return value for the generated functions
    public typealias QueryType = KeychainKeyDescriptor
    public typealias ResultType = KeychainPrivateKey

    override public init(descriptor: KeychainKeyDescriptor, keyRef: SecKey) {
        super.init(descriptor: descriptor, keyRef: keyRef)
        attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }

    public override init(SecItemAttributes attributes: SecItemAttributes) throws {
        try super.init(SecItemAttributes: attributes)
        self.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
    }
}

public protocol KeyPair {
    typealias PrivKeyType : PrivateKey
    typealias PubKeyType  : PublicKey
    typealias KeyPairTransportClass
    typealias GeneratorDescriptorClass
    var privateKey: PrivKeyType! { get }
    var publicKey: PubKeyType!  { get }
    init (publicKey: PubKeyType, privateKey: PrivKeyType)
    static func generateKeyPair(descriptor: GeneratorDescriptorClass) throws -> KeyPairTransportClass
}


extension KeyPair where Self : KeyPair {
}


public func secEnsureOK(status: OSStatus) throws {
    if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
}



/**
An instance of an IOS Keypair
*/

public class KeychainKeyPair : KeychainItem, KeyPair, KeychainFindable {
    public private(set) var privateKey: KeychainPrivateKey!
    public private(set) var publicKey:  KeychainPublicKey!

    public class func generateKeyPair(descriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair {
        var publicKeyRef  : SecKey?
        var privateKeyRef : SecKey?

        try secEnsureOK(SecKeyGeneratePair(descriptor.keychainMatchPropertyValues(), &publicKeyRef, &privateKeyRef))

        return try findInKeychain(descriptor)!
        
    }

    public class func findInKeychain(matchingDescriptor: KeychainKeyPairDescriptor) throws -> KeychainKeyPair? {
        let privateKey = try KeychainPrivateKey.findInKeychain(matchingDescriptor.privateKeyDescriptor()  as KeychainPrivateKey.QueryType)
        let publicKey = try KeychainPublicKey.findInKeychain(matchingDescriptor.publicKeyDescriptor())
        if let privateKey = privateKey, let publicKey = publicKey {
            return KeychainKeyPair(publicKey: publicKey as KeychainPublicKey, privateKey: privateKey as KeychainPrivateKey)
        }
        return nil
    }


    public init(descriptor: KeychainKeyPairDescriptor, publicKeyRef: SecKey, privateKeyRef: SecKey) {
        self.privateKey = KeychainPrivateKey(descriptor: descriptor, keyRef: privateKeyRef)
        self.publicKey  = KeychainPublicKey(descriptor: descriptor, keyRef: publicKeyRef)
        super.init(securityClass: SecurityClass.Key)
    }

    public required init (publicKey: KeychainPublicKey, privateKey: KeychainPrivateKey) {
        self.privateKey = privateKey
        self.publicKey  = publicKey
        super.init(securityClass: SecurityClass.Key)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)

        self.privateKey = try KeychainPrivateKey(SecItemAttributes: attributes)
        self.publicKey  = try KeychainPublicKey(SecItemAttributes: attributes)
    }
}


//MARK: Key Pair Descriptors

public protocol KeyPairQueryable {
    func privateKeyDescriptor() -> KeychainKeyDescriptor
    func publicKeyDescriptor() -> KeychainKeyDescriptor
}

public class KeychainKeyPairDescriptor : KeychainKeyDescriptor, KeyPairQueryable {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func privateKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor(keyDescriptor: self)
        descriptor.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
        return descriptor
    }

    public func publicKeyDescriptor() -> KeychainKeyDescriptor {
        let descriptor = KeychainKeyDescriptor(keyDescriptor: self)
        descriptor.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
        return descriptor
    }
}


public class TemporaryKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: false)
    }
}

public class PermanentKeychainKeyPairDescriptor : KeychainKeyPairDescriptor {
    /**
    :param:   keyType     Type of key pair to generate (RSA or EC)
    :param:   keySize     Size of the key to generate
    :param:   keyLabel    A searchable label for the key pair
    :param:   keyAppTag
    :returns: keyAppLabel The kSecAttrAppLabel to add to the keychain item. By default this is the hash of the public key and should be set to nit
    */
    public init(accessible: Accessible, privateKeyAccessControl: SecAccessControl?,publicKeyAccessControl: SecAccessControl?, keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
        attributes[String(kSecAttrAccessible)] = accessible.rawValue
        if (privateKeyAccessControl != nil) {
            attributes[String(kSecPrivateKeyAttrs)] = [ String(kSecAttrAccessControl): privateKeyAccessControl! ]
        }
        if (publicKeyAccessControl != nil) {
            attributes[String(kSecPublicKeyAttrs)] = [ String(kSecAttrAccessControl): publicKeyAccessControl! ]
        }
    }
}



