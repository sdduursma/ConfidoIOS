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
    public class func secItemCopyMatchingItem<T>(query: KeyChainPropertiesData) -> (KeychainStatus, T?) {
        let dictionary = NSMutableDictionary()
        dictionary[String(kSecMatchLimit)]       = kSecMatchLimitOne
        dictionary.addEntriesFromDictionary(query)


        var result: AnyObject?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(dictionary, UnsafeMutablePointer($0)) }
            )
        if status == .OK, let returnValue = result as? T {
            return (status, returnValue)
        }
        return (status, nil)
    }

    public class func secItemCopyMatchingItems(query: KeyChainPropertiesData) -> (KeychainStatus, [SecItemAttributes]) {
        let attributes = NSMutableDictionary()
        attributes[String(kSecMatchLimit)]       = kSecMatchLimitAll
        attributes.addEntriesFromDictionary(query)

        var result: AnyObject?

        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecItemCopyMatching(attributes, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [SecItemAttributes] {
            return (status, items)
        }
        return (status, [])
    }


    public class func secItemAdd(attributes: KeychainItemData) -> (KeychainStatus, AnyObject?) {
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


        return (.OK,[])
//        println(status)
//        println(result)
//        if status == .OK {
//            return (status, nil)
//        }
//        return (status, [])
    }




    public class func secItemDelete(query: KeyChainPropertiesData) -> KeychainStatus {
        let dictionary = NSMutableDictionary()
        dictionary.addEntriesFromDictionary(query)

        let status = KeychainStatus.statusFromOSStatus(SecItemDelete(dictionary))
        return status
    }

    public class func secKeyGeneratePair(query: KeyChainPropertiesData) -> (KeychainStatus, SecKey?, SecKey?) {
        var publicKeyRef  : SecKey?
        var privateKeyRef : SecKey?

        let status = KeychainStatus.statusFromOSStatus(
            SecKeyGeneratePair(query, &publicKeyRef, &privateKeyRef))
        if status == .OK {
            return (status, publicKeyRef, privateKeyRef)
        } else {
            return (status, nil, nil)
        }

    }

    public class func secPKCS12Import(pkcs12Data: NSData, options: KeyChainPropertiesData) -> (KeychainStatus, [SecItemAttributes]) {
        var result: NSArray?
        let status = KeychainStatus.statusFromOSStatus(
            withUnsafeMutablePointer(&result) { SecPKCS12Import(pkcs12Data, options, UnsafeMutablePointer($0)) }
        )
        if status == .OK, let items = result as? [SecItemAttributes]
        {
            return (status, items)
        }
        return (status, [])
    }


}

public class Keychain {
    public class func keyChainItems(securityClass: SecurityClass) -> (KeychainStatus, [KeychainItem]) {
        var query : KeyChainPropertiesData = [ : ]
        query[String(kSecClass)]               = SecurityClass.kSecClass(securityClass)
        query[String(kSecReturnData)]          = kCFBooleanFalse
        query[String(kSecReturnAttributes)]    = kCFBooleanTrue
        query[String(kSecReturnRef)]           = kCFBooleanFalse
        query[String(kSecReturnPersistentRef)] = kCFBooleanFalse
        query[String(kSecMatchLimit)]          = kSecMatchLimitAll

        let result   : KeychainStatus
        let itemDicts: [SecItemAttributes]

        (result, itemDicts) = SecurityWrapper.secItemCopyMatchingItems(query)

        var items : [KeychainItem] = []

        for itemDict in itemDicts {
            if let item = makeKeyChainItem(securityClass, keychainItemAttributes: itemDict) {
                items.append(item)
            }
        }
        if result == .OK || result == .ItemNotFoundError {
            return (.OK, items)
        } else {
            return (result, items)
        }
    }

    public class func fetchMatchingItem(thatMatchesProperties properties: KeychainMatchable) -> (KeychainStatus, KeychainItem?) {
        var query : KeyChainPropertiesData = [ : ]

        query[String(kSecClass)]            = SecurityClass.kSecClass(properties.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanFalse
        query[String(kSecReturnRef)]        = kCFBooleanTrue
        query[String(kSecReturnAttributes)] = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne

        query += properties.keychainMatchPropertyValues()

        let (result, itemDict): (KeychainStatus, SecItemAttributes?) = SecurityWrapper.secItemCopyMatchingItem(query)

        if result == .OK {
            return (KeychainStatus.OK, makeKeyChainItem(properties.securityClass, keychainItemAttributes:  itemDict!))
        }

        return (result, nil)
    }



    public class func deleteKeyChainItem(itemSpecifier specifier: KeychainMatchable) -> KeychainStatus {
        return SecurityWrapper.secItemDelete(specifier.keychainMatchPropertyValues())
    }

    class func makeKeyChainItem(securityClass: SecurityClass, keychainItemAttributes attributes: SecItemAttributes) -> KeychainItem? {
        return KeychainItem.itemFromAttributes(securityClass, SecItemAttributes: attributes)
    }


    public class func generateKeyPair(properties: KeychainKeyPairProperties) throws -> (KeychainStatus, KeychainKeyPair?) {

        let (result, publicKeyRef, privateKeyRef) = SecurityWrapper.secKeyGeneratePair(properties.keychainMatchPropertyValues())

        if result == .OK {
            return (result, try KeychainKeyPair.findInKeychain(properties))
        } else {
            return (result, nil)
        }
    }


    public class func addIdentity(identity: IdentityImportSpecifier) -> (KeychainStatus, Identity?) {
        var item : KeyChainPropertiesData = [ : ]
        item[String(kSecReturnPersistentRef)] = NSNumber(bool: true);

        item += identity.keychainMatchPropertyValues()

        //There seems to be a bug in the keychain that causes the SecItemAdd for Identities to fail silently when kSecClass is specified :S
        item.removeValueForKey(String(kSecClass))

        let (result, itemRefs): (KeychainStatus, AnyObject?) = SecurityWrapper.secItemAdd(item)

        return (.OK, nil)

    }

    public class func keyData(key: KeychainKey) -> (KeychainStatus, NSData?) {
        var keyRef: Unmanaged<AnyObject>?

        var query : KeyChainPropertiesData = [ : ]

        let specifier = key.keychainMatchPropertyValues()
        query[String(kSecClass)]            = SecurityClass.kSecClass(key.securityClass)
        query[String(kSecReturnData)]       = kCFBooleanTrue
        query[String(kSecMatchLimit)]       = kSecMatchLimitOne
        query += specifier.keychainMatchPropertyValues()

        let (result, itemDict): (KeychainStatus, NSData?) = SecurityWrapper.secItemCopyMatchingItem(query)

        if result == .OK {
            return (.OK, itemDict)
        }

        return (result, nil)
    }

    public class func importP12Identity(identity: P12Identity) -> IdentityReference? {
        var options : KeyChainPropertiesData = [ : ]

        options[kSecImportExportPassphrase as String] = identity.importPassphrase

        let (result, itemRefs) = SecurityWrapper.secPKCS12Import(identity.p12EncodedIdentityData, options: options)
        if itemRefs.count == 1 {
            let item = itemRefs[0]
            let identityRef : SecIdentityRef = itemRefs[0][kSecImportItemIdentity as String] as! SecIdentityRef
            return IdentityReference(reference: identityRef)
        }
        return nil
    }

    public class func deleteAllItemsOfClass(securityClass: SecurityClass) -> Int {
        return 0
    }
}


