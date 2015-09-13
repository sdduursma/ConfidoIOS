//
//  KeychainKey.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation


public class KeychainKey : KeychainItem, KeychainKeyClassProperties {
    public class func keychainKeyFromAttributes(SecItemAttributes attributes: SecItemAttributes) -> KeychainKey? {
        let keyClass = KeyClass.keyClass(attributes[String(kSecAttrKeyClass)])
        switch keyClass {
        case .PrivateKey: return KeychainPrivateKey(SecItemAttributes: attributes)
        case .PublicKey:  return KeychainPublicKey(SecItemAttributes: attributes)
        default:          return KeychainKey(SecItemAttributes: attributes)
        }
    }

    var keySecKey: SecKey?

    public init(properties: KeychainKeyProperties, keyRef: SecKey) {
        keySecKey = keyRef
        super.init(securityClass: .Key,  byCopyingAttributes: properties)
    }

    public init(SecItemAttributes attributes: SecItemAttributes) {
        super.init(securityClass: SecurityClass.Key, SecItemAttributes: attributes)
        self.keySecKey = KeychainKey.getKeySecKey(keychainAttributes: attributes)
    }

    class func getKeySecKey(keychainAttributes attributes: NSDictionary) -> SecKey? {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecKeyGetTypeID() {
                return (valueRef as! SecKey)
            }
        }
        return nil
    }

    override public func specifierMatchingProperties() -> Set<String> {
       return kKeyItemMatchingProperties
    }


    public lazy var keyData: NSData? = {
        // It is possible that a key is not permanent, then there isn't any data to return
        let (result, optionalData) = Keychain.keyData(self)
        return optionalData
        }()
}


