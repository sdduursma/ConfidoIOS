//
//  Keychain.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 18/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

public typealias SecItemAttributes    = [ String : AnyObject]
public typealias ItemReference     = AnyObject
public typealias KeyChainPropertiesData = [ String : AnyObject]
public typealias KeychainItemData  = [ String : AnyObject]

func += <KeyType, ValueType> (inout left: Dictionary<KeyType, ValueType>, right: Dictionary<KeyType, ValueType>) {
    for (k, v) in right {
        left.updateValue(v, forKey: k)
    }
}

public class SecurityWrapper {
    public class func secItemCopyMatchingItem<T>(query: KeyChainPropertiesData) throws -> T? {
        let dictionary = NSMutableDictionary()
        dictionary[String(kSecMatchLimit)]       = kSecMatchLimitOne
        dictionary.addEntriesFromDictionary(query)


        var result: AnyObject?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(dictionary, UnsafeMutablePointer($0)) }
            )
        if status == .OK, let returnValue = result as? T {
            return returnValue
        } else if status == .OK {
            return nil
        }
        throw status
    }

    public class func secItemCopyMatchingItems(query: KeyChainPropertiesData) throws -> [SecItemAttributes] {
        let attributes = NSMutableDictionary()
        attributes[String(kSecMatchLimit)]       = kSecMatchLimitAll
        attributes.addEntriesFromDictionary(query)

        var result: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(attributes, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [SecItemAttributes] {
            return items
        } else if status == .OK {
            return []
        }
        throw status
    }


    public class func secItemAdd(attributes: KeychainItemData) throws -> AnyObject?  {
        var persistedRef: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&persistedRef) { SecItemAdd(attributes, UnsafeMutablePointer($0)) }
        )

        if status == .OK {
            print(persistedRef)
            if let data = persistedRef as? NSData {
                print(data)
            }
        }


        return []
//        println(status)
//        println(result)
//        if status == .OK {
//            return (status, nil)
//        }
//        return (status, [])
    }




    public class func secItemDelete(query: KeyChainPropertiesData) throws  {
        let dictionary = NSMutableDictionary()
        dictionary.addEntriesFromDictionary(query)

        let status = KeychainStatus.statusFromOSStatus(SecItemDelete(dictionary))
        if status == .OK {
            return
        }
        throw status
    }

    public class func secKeyGeneratePair(query: KeyChainPropertiesData) throws -> (SecKey?, SecKey?) {
        var publicKeyRef  : SecKey?
        var privateKeyRef : SecKey?

        let status = KeychainStatus.statusFromOSStatus(
            SecKeyGeneratePair(query, &publicKeyRef, &privateKeyRef))
        if status == .OK {
            return (publicKeyRef, privateKeyRef)
        }
        throw status
    }

    public class func secPKCS12Import(pkcs12Data: NSData, options: KeyChainPropertiesData) throws -> [SecItemAttributes] {
        var result: NSArray?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecPKCS12Import(pkcs12Data, options, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [SecItemAttributes]
        {
            return items
        }
        else if status == .OK {
            return []
        }
        throw status
    }
}




public class Keychain {
    public class func keyChainItems(securityClass: SecurityClass) throws -> [KeychainItem] {
        var query : KeyChainPropertiesData = [ : ]
        query[String(kSecClass)]               = SecurityClass.kSecClass(securityClass)
        query[String(kSecReturnData)]          = kCFBooleanFalse
        query[String(kSecReturnAttributes)]    = kCFBooleanTrue
        query[String(kSecReturnRef)]           = kCFBooleanFalse
        query[String(kSecReturnPersistentRef)] = kCFBooleanFalse
        query[String(kSecMatchLimit)]          = kSecMatchLimitAll

        let itemDicts: [SecItemAttributes]

        itemDicts = try SecurityWrapper.secItemCopyMatchingItems(query)

        var items : [KeychainItem] = []

        for itemDict in itemDicts {
            if let item = makeKeyChainItem(securityClass, keychainItemAttributes: itemDict) {
                items.append(item)
            }
        }
        return items
        //TODO: Test and implement ItemNotFound
    }

    public class func fetchMatchingItem(thatMatchesProperties properties: KeychainMatchable) throws -> KeychainItem? {
        var query : KeyChainPropertiesData = [ : ]

        query[String(kSecClass)]            = SecurityClass.kSecClass(properties.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanFalse
        query[String(kSecReturnRef)]        = kCFBooleanTrue
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne

        query += properties.keychainMatchPropertyValues()

        let itemDict : SecItemAttributes? = try SecurityWrapper.secItemCopyMatchingItem(query)

        return makeKeyChainItem(properties.securityClass, keychainItemAttributes:  itemDict!)
    }



    public class func deleteKeyChainItem(itemSpecifier specifier: KeychainMatchable) throws  {
        try SecurityWrapper.secItemDelete(specifier.keychainMatchPropertyValues())
    }

    class func makeKeyChainItem(securityClass: SecurityClass, keychainItemAttributes attributes: SecItemAttributes) -> KeychainItem? {
        return KeychainItem.itemFromAttributes(securityClass, SecItemAttributes: attributes)
    }


    public class func generateKeyPair(properties: KeychainKeyPairProperties) throws -> KeychainKeyPair? {

        let (publicKeyRef, privateKeyRef) = try SecurityWrapper.secKeyGeneratePair(properties.keychainMatchPropertyValues())
        return try KeychainKeyPair.findInKeychain(properties)
    }


//    public class func addIdentity(identity: IdentityImportSpecifier) throws -> (KeychainStatus, Identity?) {
//        var item : KeyChainPropertiesData = [ : ]
//        item[String(kSecReturnPersistentRef)] = NSNumber(bool: true);
//
//        item += identity.keychainMatchPropertyValues()
//
//        //There seems to be a bug in the keychain that causes the SecItemAdd for Identities to fail silently when kSecClass is specified :S
//        item.removeValueForKey(String(kSecClass))
//
//        let itemRefs: AnyObject? = try SecurityWrapper.secItemAdd(item)
//
//    }

    public class func keyData(key: KeychainKey) throws -> NSData? {
        var keyRef: Unmanaged<AnyObject>?

        var query : KeyChainPropertiesData = [ : ]

        let specifier = key.keychainMatchPropertyValues()
        query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += specifier.keychainMatchPropertyValues()

        let keyData: NSData? = try SecurityWrapper.secItemCopyMatchingItem(query)
        return keyData

    }

    public class func importP12Identity(identity: P12Identity) throws -> IdentityReference? {
        var options : KeyChainPropertiesData = [ : ]

        options[kSecImportExportPassphrase as String] = identity.importPassphrase

        let itemRefs = try SecurityWrapper.secPKCS12Import(identity.p12EncodedIdentityData, options: options)
        if itemRefs.count == 1 {
            let identityRef : SecIdentityRef = itemRefs[0][kSecImportItemIdentity as String] as! SecIdentityRef
            return IdentityReference(reference: identityRef)
        }
        return nil
    }

    public class func deleteAllItemsOfClass(securityClass: SecurityClass) -> Int {
        return 0
    }
}


