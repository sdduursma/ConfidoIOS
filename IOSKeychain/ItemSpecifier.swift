//
//  ItemSpecifier.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation


/*
Base class for all queries to the keychain.
*/



public class KeychainKeyProperties : KeychainProperties {

    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }


    public init(keyProperties: KeychainKeyProperties) {
        super.init(properties: keyProperties)
    }

    public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil,
        keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Key, itemLabel: keyLabel)
            if keyType != nil {
                attributes[String(kSecAttrKeyType)]          = keyType!.rawValue
            }
            if keySize != nil  {
                attributes[String(kSecAttrKeySizeInBits)]    = keySize!
            }
            if keyClass != nil {
                attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(keyClass!)
            }
            if keyAppLabel != nil {
                attributes[String(kSecAttrApplicationLabel)] = KeychainKeyProperties.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag!
            }
    }

}

public protocol KeyPairQueryable {
    func privateKeyQueryProperties() -> KeychainKeyProperties
    func publicKeyQueryProperties() -> KeychainKeyProperties
}

public class KeychainKeyPairProperties : KeychainKeyProperties, KeyPairQueryable {
    override public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil, keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize, keyClass: keyClass, keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel)
    }

    public func privateKeyQueryProperties() -> KeychainKeyProperties {
        let specifier = KeychainKeyProperties(keyProperties: self)
        specifier.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PrivateKey)
        return specifier
    }

    public func publicKeyQueryProperties() -> KeychainKeyProperties {
        let specifier = KeychainKeyProperties(keyProperties: self)
        specifier.attributes[String(kSecAttrKeyClass)] = KeyClass.kSecAttrKeyClass(.PublicKey)
        return specifier
    }
}

public class TemporaryKeychainKeyPairProperties : KeychainKeyPairProperties {
    public init(keyType: KeyType, keySize: Int) {
        super.init(keyType: keyType, keySize: keySize)
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: false)
    }
}

public class PermanentKeychainKeyPairProperties : KeychainKeyPairProperties {
    public init(keyType: KeyType, keySize: Int, keyLabel: String , keyAppTag: String? = nil, keyAppLabel: String? = nil) {
        super.init(keyType: keyType, keySize: keySize,keyLabel: keyLabel, keyAppTag: keyAppTag, keyAppLabel: keyAppLabel )
        attributes[String(kSecAttrIsPermanent)] = NSNumber(bool: true)
    }
}




