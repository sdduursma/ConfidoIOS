//
//  KeyPairTests.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//

import UIKit
import XCTest
import ConfidoIOS

class KeyPairTests: BaseTests {

    func testGenerateNamedRSAKeyPair() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.whenUnlockedThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
        var keyPair : KeychainKeyPair!
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)


        let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
        var keyItem: KeychainItem?
        keyItem = try! Keychain.fetchItem(matchingDescriptor: keyDescriptor)
        XCTAssertNotNil(keyItem)

        XCTAssertEqual(keyPair.privateKey.keyType, KeyType.rsa)
        XCTAssertEqual(keyPair.publicKey.keyType, KeyType.rsa)


        XCTAssertEqual(keyPair.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair.publicKey.keySize, 1024)

        XCTAssertNotNil(keyPair.privateKey.itemLabel)
        XCTAssertEqual(keyPair.privateKey.itemLabel!, "AAA")

        XCTAssertNotNil(keyPair.privateKey.keyAppTag)
        XCTAssertEqual(keyPair.privateKey.keyAppTag!, "BBB")

        XCTAssertNil(keyPair.privateKey.keyAppLabelString)
        XCTAssertNotNil(keyPair.publicKey.keyAppLabelString)
        XCTAssertEqual(keyPair.publicKey.keyAppLabelString!, "CCC")

        XCTAssertEqual(keyPair.publicKey.itemAccessGroup, "com.curoo.ConfidoIOSTestsHostApp")
        XCTAssertEqual(keyPair.publicKey.itemAccessible, Accessible.whenUnlockedThisDeviceOnly)

        let publicKeyData = keyPair.publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        XCTAssertEqual(publicKeyData!.count,140)

        let signature = try! keyPair.privateKey.sign(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]))
        print(signature)

        var verified = try! keyPair.publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
        XCTAssertTrue(verified)

        verified = try! keyPair.publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
        XCTAssertFalse(verified)

        let cipherTextUnderPublicKey = try! keyPair.publicKey.encrypt(ByteBuffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")

        let decryptedText = try! keyPair.privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
        XCTAssertEqual([1,2,3,4], decryptedText.values)
    }

    func testGenerateNamedECKeyPairSignVerify() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.whenUnlockedThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: KeyType.elypticCurve, keySize: 256, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
        var keyPair : KeychainKeyPair!
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)


        let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
        var keyItem: KeychainItem?
        keyItem = try! Keychain.fetchItem(matchingDescriptor: keyDescriptor)
        XCTAssertNotNil(keyItem)

        XCTAssertEqual(keyPair.privateKey.keyType, KeyType.elypticCurve)
        XCTAssertEqual(keyPair.publicKey.keyType, KeyType.elypticCurve)


        XCTAssertEqual(keyPair.privateKey.keySize, 256)
        XCTAssertEqual(keyPair.publicKey.keySize, 256)


        let publicKeyData = keyPair.publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        XCTAssertEqual(publicKeyData!.count,65)

        let signature = try! keyPair.privateKey.sign(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]))
        print("Signature: \(signature.hexString)")

        var verified = try! keyPair.publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
        XCTAssertTrue(verified)

        verified = try! keyPair.publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
        XCTAssertFalse(verified)
    }


    func testGenerateNamedECKeyPairEncryptDecrypt() {
        // This test fails because it seems that Apple has not implemented encrypting/decrypting (only signing) for EC keys.
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.whenUnlockedThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: KeyType.elypticCurve, keySize: 256, keyLabel: "AAA", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
        var keyPair : KeychainKeyPair!
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)


        let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
        var keyItem: KeychainItem?
        keyItem = try! Keychain.fetchItem(matchingDescriptor: keyDescriptor)
        XCTAssertNotNil(keyItem)

        XCTAssertEqual(keyPair.privateKey.keyType, KeyType.elypticCurve)
        XCTAssertEqual(keyPair.publicKey.keyType, KeyType.elypticCurve)


        let publicKeyData = keyPair.publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        XCTAssertEqual(publicKeyData!.count,65)


        let cipherTextUnderPublicKey = try! keyPair.publicKey.encrypt(ByteBuffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")

        let decryptedText = try! keyPair.privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
        XCTAssertEqual([1,2,3,4], decryptedText.values)
    }



    func testGenerateKeyPairDifferentLabels() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)
        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: .whenUnlockedThisDeviceOnly,
            keyLabel: "KPriv", privateKeyAppTag: nil, privateKeyAccessControl: nil,
            publicKeyAppLabel: "KPub", publicKeyAppTag: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 1024)

        var keyPair : KeychainKeyPair!
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)


        let privKeyDescriptor = KeychainKeyDescriptor(keyClass: KeyClass.privateKey, keyLabel: "KPriv")
        var privKeyItem: KeychainItem?
        privKeyItem = try! Keychain.fetchItem(matchingDescriptor: privKeyDescriptor)
        XCTAssertNotNil(privKeyItem)

        XCTAssert(privKeyItem is KeychainPrivateKey)

        let pubKeyDescriptor = KeychainKeyDescriptor(keyClass: KeyClass.publicKey, keyLabel: "KPriv", keyAppLabel: "KPub")
        var pubKeyItem: KeychainItem?
        pubKeyItem = try! Keychain.fetchItem(matchingDescriptor: pubKeyDescriptor)
        XCTAssertNotNil(pubKeyItem)

        XCTAssert(pubKeyItem is KeychainPublicKey)
        let publicKey  =  pubKeyItem as! KeychainPublicKey
        let privateKey = privKeyItem as! KeychainPrivateKey

        let publicKeyData = publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        XCTAssertEqual(publicKeyData!.count,140)

        let signature = try! privateKey.sign(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]))
        print(signature)

        var verified = try! publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8]), signature: signature)
        XCTAssertTrue(verified)

        verified = try! publicKey.verify(ByteBuffer(bytes:[1,2,3,4,5,6,7,8,9]), signature: signature)
        XCTAssertFalse(verified)

        let cipherTextUnderPublicKey = try! publicKey.encrypt(ByteBuffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")

        let decryptedText = try! privateKey.decrypt(cipherTextUnderPublicKey, padding: SecPadding.OAEP)
        XCTAssertEqual([1,2,3,4], decryptedText.values)
    }

    func testGenerateNamedKeyPairNoKeyLabel() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(
            accessible: Accessible.alwaysThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 1024, keyLabel: "AAA")
        var keyPair : KeychainKeyPair?
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)

        let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
        var keyItem: KeychainItem?
        keyItem = try! Keychain.fetchItem(matchingDescriptor: keyDescriptor)
        XCTAssertNotNil(keyItem)

        XCTAssertEqual(keyPair!.privateKey.keyType, KeyType.rsa)
        XCTAssertEqual(keyPair!.publicKey.keyType, KeyType.rsa)


        XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair!.publicKey.keySize, 1024)

        XCTAssertNotNil(keyPair!.privateKey.itemLabel)
        XCTAssertEqual(keyPair!.privateKey.itemLabel!, "AAA")

        XCTAssertNotNil(keyPair!.privateKey.keyAppTag)
        XCTAssertEqual(keyPair!.privateKey.keyAppTag!, "")

        XCTAssertNotNil(keyPair!.privateKey.keyAppLabelData)
        //The keyAppLabel is equal to the hash of the public key by default

        let publicKeyData = keyPair!.publicKey.keyData
        XCTAssertNotNil(publicKeyData)


        XCTAssertEqual(publicKeyData!.count,140)
    }


    func testGenerateUnnamedKeyPair() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = TemporaryKeychainKeyPairDescriptor(keyType: .rsa, keySize: 1024)
        let keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        items =  try! Keychain.keyChainItems(.key)
        // Temporary keys are not stored in the keychain
        XCTAssertEqual(items.count,0)

        XCTAssertEqual(keyPair.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair.publicKey.keySize, 1024)


        // There is no way to extract the data of a key for non-permanent keys
        let publicKeyData = keyPair.publicKey.keyData
        XCTAssertNil(publicKeyData)
    }


    func testDuplicateKeyPairMatching() {
        clearKeychainItems(.key)
        var items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        var keypairDescriptor = PermanentKeychainKeyPairDescriptor(
            accessible: Accessible.alwaysThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
        var keyPair : KeychainKeyPair? = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)


        items = try! Keychain.keyChainItems(.key)
        XCTAssertEqual(items.count,2)

        // Test that labels make the keypair unique
        do {
            do {
                keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
                XCTFail("Expected DuplicateItemError")
            } catch KeychainStatus.duplicateItemError {
                // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
            }
        } catch let error {
            XCTFail("Unexpected Error \(error)")
        }

        // different keySize
        keypairDescriptor = PermanentKeychainKeyPairDescriptor(
            accessible: Accessible.alwaysThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", publicKeyAppLabel: "CCC")
        keyPair = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)
    }


    func testExportCSR (){
        clearKeychainItems(.key)
        let items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,0)

        let keypairDescriptor = PermanentKeychainKeyPairDescriptor(
            accessible: Accessible.alwaysThisDeviceOnly,
            privateKeyAccessControl: nil, publicKeyAccessControl: nil,
            keyType: .rsa, keySize: 1024, keyLabel: "KeyPair for CSR")
        let keyPair : KeychainKeyPair! = try! KeychainKeyPair.generateKeyPair(keypairDescriptor)
        XCTAssertNotNil(keyPair)

        let attributes = [
            "UID" : "Test Device",
            "CN" : "Expend Device ABCD" ]

        let csr = try! OpenSSL.generateCSR(withPrivateKeyData: keyPair.privateKey.keyData(), csrData: attributes)
        XCTAssertNotNil(csr)
        let csrString : NSString! = NSString(data: csr, encoding: String.Encoding.utf8.rawValue)
        XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        print("CSR:")
        print(csrString)
    }

    func testPublicKeyFromDERFile() {
        clearKeychainItems(.key)
        let publicKeyData = try! contentsOfBundleResource("public-key", ofType: "der")
        let publicKey = try! KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData, keyLabel: "build-key")
        let cipherTextUnderPublicKey = try! publicKey.encrypt(ByteBuffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")
    }


    func testTwoPublicKeysDifferentAppTagsSameLabel() {
        // In the keychain, keyAppTag is unique, so no two items can share it.
        // itemLabel is not unique, so two items can have the same label
        var items = try! Keychain.keyChainItems(SecurityClass.key)

        clearKeychainItems(.key)
        let publicKeyData = try! contentsOfBundleResource("public-key", ofType: "der")
        let publicKey = try! KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData, keyLabel: "build-key", keyAppTag: "build")

        items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,1)

        let cipherTextUnderPublicKey = try! publicKey.encrypt(ByteBuffer(bytes:[1,2,3,4]), padding: SecPadding.OAEP)
        print("Cipher under public key: \(cipherTextUnderPublicKey)")

        let publicKeyData2 = try! contentsOfBundleResource("development-build-public-key", ofType: "der")
        
        let publicKey2 = try! KeychainPublicKey.importRSAPublicKey(derEncodedData: publicKeyData2, keyLabel: "build-key", keyAppTag: "build-1")
        XCTAssertNotNil(publicKey2)
        items = try! Keychain.keyChainItems(SecurityClass.key)
        XCTAssertEqual(items.count,2)
        let matchingDescriptor = PublicKeyMatchingDescriptor(keyLabel: "build-key", keyAppTag: nil)
        var keys = KeychainPublicKey.existingKeys(matchingDescriptor)
        XCTAssertEqual(keys.count,2)
        
        try! Keychain.deleteKeyChainItem(itemDescriptor: matchingDescriptor)
        keys = KeychainPublicKey.existingKeys(matchingDescriptor)
        XCTAssertEqual(keys.count,0)
        
    }
    
    
    
}
