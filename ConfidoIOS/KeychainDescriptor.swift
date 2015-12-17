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


public class KeychainKeyDescriptor : KeychainDescriptor {
    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }


    public init(keyDescriptor: KeychainKeyDescriptor) {
        super.init(descriptor: keyDescriptor)
    }

    public init(keyType: KeyType? = nil, keySize: Int? = nil, keyClass: KeyClass? = nil,
        keyLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Key, itemLabel: keyLabel)
            if let keyType = keyType {
                attributes[String(kSecAttrKeyType)]          = keyType.rawValue
            }
            if let keySize = keySize {
                attributes[String(kSecAttrKeySizeInBits)]    = keySize
            }
            if let keyClass = keyClass {
                attributes[String(kSecAttrKeyClass)]         = KeyClass.kSecAttrKeyClass(keyClass)
            }
            if let keyAppLabel = keyAppLabel {
                attributes[String(kSecAttrApplicationLabel)] = KeychainKeyDescriptor.encodeKeyAppLabel(keyAppLabel)
            }
            if let keyAppTag = keyAppTag {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag
            }
    }
}






