//
//  Itemdescriptor.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 21/08/2015.
//

import Foundation


/*
Base class for queries to the keychain. Used to derive things like specifications for generating keys, searching the IOS Keychain, etc.
*/


open class KeychainKeyDescriptor : KeychainDescriptor {
    class func encodeKeyAppLabel(_ keyAppLabel: String?) -> Data? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.data(using: String.Encoding.utf8, allowLossyConversion: true)
    }


    public init(keyDescriptor: KeychainKeyDescriptor) {
        super.init(descriptor: keyDescriptor)
    }

    public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil,
        keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .key, itemLabel: keyLabel)
            if let keyType = keyType {
                attributes[String(kSecAttrKeyType)]          = keyType.rawValue as AnyObject?
            }
            if let keySize = keySize {
                attributes[String(kSecAttrKeySizeInBits)]    = keySize as AnyObject?
            }
            if let keyClass = keyClass {
                attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(keyClass)
            }
            if let keyAppLabel = keyAppLabel {
                attributes[String(kSecAttrApplicationLabel)] = KeychainKeyDescriptor.encodeKeyAppLabel(keyAppLabel) as AnyObject?
            }
            if let keyAppTag = keyAppTag {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag as AnyObject?
            }
    }
}






