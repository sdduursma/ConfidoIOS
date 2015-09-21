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

    func testGenerateNamedKeyPair() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.WhenUnlockedThisDeviceOnly, accessControl: nil, keyType: .RSA, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", keyAppLabel: "CCC")
            var keyPair : KeychainKeyPair?
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)


            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair!.privateKey.keyType, KeyType.RSA)
            XCTAssertEqual(keyPair!.publicKey.keyType, KeyType.RSA)


            XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair!.publicKey.keySize, 1024)

            XCTAssertNotNil(keyPair!.privateKey.itemLabel)
            XCTAssertEqual(keyPair!.privateKey.itemLabel!, "AAA")

            XCTAssertNotNil(keyPair!.privateKey.keyAppTag)
            XCTAssertEqual(keyPair!.privateKey.keyAppTag!, "BBB")

            XCTAssertNotNil(keyPair!.privateKey.keyAppLabelString)
            XCTAssertEqual(keyPair!.privateKey.keyAppLabelString!, "CCC")

            XCTAssertEqual(keyPair!.publicKey.itemAccessGroup, "")
            XCTAssertEqual(keyPair!.publicKey.itemAccessible, Accessible.WhenUnlockedThisDeviceOnly)

            let publicKeyData = keyPair!.publicKey.keyData
            XCTAssertNotNil(publicKeyData)

            XCTAssertEqual(publicKeyData!.length,140)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }


    }

    func testGenerateNamedKeyPairNoKeyLabel() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.AlwaysThisDeviceOnly, accessControl: nil, keyType: .RSA, keySize: 1024, keyLabel: "AAA")
            var keyPair : KeychainKeyPair?
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            let keyDescriptor = KeychainKeyDescriptor(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchItem(matchingDescriptor: keyDescriptor)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair!.privateKey.keyType, KeyType.RSA)
            XCTAssertEqual(keyPair!.publicKey.keyType, KeyType.RSA)


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


            XCTAssertEqual(publicKeyData!.length,140)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
        
        
    }

    
    func testGenerateUnnamedKeyPair() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keypairDescriptor = TemporaryKeychainKeyPairDescriptor(keyType: .RSA, keySize: 1024)
            let keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)

            items =  try Keychain.keyChainItems(.Key)
            // Temporary keys are not stored in the keychain
            XCTAssertEqual(items.count,0)

            XCTAssertEqual(keyPair.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair.publicKey.keySize, 1024)


            // There is no way to extract the data of a key for non-permanent keys
            let publicKeyData = keyPair.publicKey.keyData
            XCTAssertNil(publicKeyData)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testDuplicateKeyPairMatching() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            var keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.AlwaysThisDeviceOnly, accessControl: nil, keyType: .RSA, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
            var keyPair : KeychainKeyPair? = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)


            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            // Test that labels make the keypair unique
            do {
                keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
                XCTFail("Expected DuplicateItemError")
            } catch KeychainStatus.DuplicateItemError {
                // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
            }

            // different keySize
            keypairDescriptor = PermanentKeychainKeyPairDescriptor(accessible: Accessible.AlwaysThisDeviceOnly, accessControl: nil, keyType: .RSA, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
            keyPair = try KeychainKeyPair.generateKeyPair(keypairDescriptor)
            XCTAssertNotNil(keyPair)
        } catch let error {
            XCTFail("Unexpected Exception \(error)")
        }

    }

}
