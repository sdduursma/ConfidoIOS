//
//  KeyChainPropertyBag.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 20/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security


public class AttributeBag {
    var attributes : [String : AnyObject] = [ : ]

    subscript(attribute: String) -> AnyObject? {
        return attributes[attribute]
    }

    init(attributeBag: AttributeBag? = nil) {
        if attributeBag != nil {
            self.attributes = attributeBag!.attributes
        }

    }

    init(keychainAttributes: NSDictionary) {
        for (key, object) in keychainAttributes {
            if let key = key as? String {
                attributes[key] = object
            }
        }
    }
}

public protocol KeychainA {
//    var accessible: LocksmithAccessibleOption? { get }
    var accessGroup: String? { get }
}

public extension KeychainA {
    var attributes : [String : AnyObject] = [ : ]

    //    var accessible: LocksmithAccessibleOption? { return nil }
    var accessGroup: String? { return nil }

    var secureStorableBaseStoragePropertyDictionary: [String: AnyObject] {
        let dictionary = [
            String(kSecAttrAccessGroup): self.accessGroup,
            String(kSecAttrAccessible): self.accessible?.rawValue
        ]

        return Dictionary(withoutOptionalValues: dictionary)
    }
}

/*
Encapsulates the attributes of a keychain item
*/
public class KeychainAttributeBag : AttributeBag {

    public var itemAccessGroup: String? {
        get { return attributes[String(kSecAttrAccessGroup)] as? String }
        set { attributes[String(kSecAttrAccessGroup)] = newValue }
    }

    public var itemLabel: String? {
        set { attributes[String(kSecAttrLabel)] = newValue }
        get { return attributes[String(kSecAttrLabel)] as? String }
    }

    public var itemCreationDate: NSDate? {
        get { return attributes[String(kSecAttrCreationDate)] as? NSDate }
    }

    public var itemModificationDate: NSDate? {
        get { return attributes[String(kSecAttrModificationDate)] as? NSDate }
    }

}



