//
//  KeyPairTests.swift
//  ExpendSecurity
//
//  Created by Rudolph van Graan on 19/08/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import UIKit
import XCTest
import IOSKeychain

class KeyPairTests: XCTestCase {

    func testGenerateNamedKeyPair() {
        clearKeychainItems(.Key)
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertEqual(items.count,0)

        let keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", keyAppLabel: "CCC")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyPair)

        (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(items.count,2)

        let keySpecifier = KeySpecifier(keyLabel: "AAA")
        var keyItem: KeychainItem?
        (status, keyItem) = Keychain.fetchMatchingItem(itemSpecifier: keySpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyItem)
        XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair!.publicKey.keySize, 1024)

        XCTAssertNotNil(keyPair!.privateKey.itemLabel)
        XCTAssertEqual(keyPair!.privateKey.itemLabel!, "AAA")

        XCTAssertNotNil(keyPair!.privateKey.keyAppTag)
        XCTAssertEqual(keyPair!.privateKey.keyAppTag!, "BBB")

        XCTAssertNotNil(keyPair!.privateKey.keyAppLabel)
        XCTAssertEqual(keyPair!.privateKey.keyAppLabel!, "CCC")

        let publicKeyData = keyPair!.publicKey.keyData
        XCTAssertNotNil(publicKeyData)

        let privateKeyData = keyPair!.privateKey.keyData
        XCTAssertNotNil(privateKeyData)

        XCTAssertEqual(publicKeyData!.length,140)
        XCTAssert(privateKeyData!.length > 0)

    }

    func testGenerateUnnamedKeyPair() {
        clearKeychainItems(.Key)
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertEqual(items.count,0)

        let keyPairSpecifier = TemporaryKeyPairSpecification(keyType: .RSA, keySize: 1024)
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyPair)

        (status, items) = Keychain.keyChainItems(.Key)
        // Temporary keys are not stored in the keychain
        XCTAssertEqual(items.count,0)

        XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
        XCTAssertEqual(keyPair!.publicKey.keySize, 1024)


        // There is no way to extract the data of a key for non-permanent keys
        let publicKeyData = keyPair!.publicKey.keyData
        XCTAssertNil(publicKeyData)

        let privateKeyData = keyPair!.privateKey.keyData
        XCTAssertNil(privateKeyData)

    }


    func testDuplicateKeyPairMatching() {
        clearKeychainItems(.Key)
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertEqual(items.count,0)

        var keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyPair)


        (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(items.count,2)

        // Test that labels make the keypair unique
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)

        // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
        XCTAssertEqual(status, KeychainStatus.DuplicateItemError)
        XCTAssertNil(keyPair)

        // different keySize
        keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyPair)


    }



    func testExportCSR (){
        clearKeychainItems(.Key)
        var (status, items) = Keychain.keyChainItems(.Key)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertEqual(items.count,0)

        let keyPairSpecifier = PermanentKeyPairSpecification(keyType: .RSA, keySize: 1024, keyLabel: "KeyPair1")
        var keyPair : KeyPair?
        (status, keyPair) = Keychain.generateKeyPair(keyPairSpecifier)
        XCTAssertEqual(status, KeychainStatus.OK)
        XCTAssertNotNil(keyPair)

        let attributes = [
            "UID" : "Test Device",
            "CN" : "Expend Device ABCD" ]

        let csr : NSData! = keyPair?.certificateSigningRequest(attributes)
        XCTAssertNotNil(csr)
        let csrString : NSString! = NSString(data: csr, encoding: NSUTF8StringEncoding)
        XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        print("CSR:")
        print(csrString)
    }


    func testImportIdentity() {

        clearKeychainItems(.Identity)
        clearKeychainItems(.Key)
        clearKeychainItems(.Certificate)

        let bundle = NSBundle(forClass: self.dynamicType)

        let keyPairPEMData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1 certificate", ofType: "x509")!)

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair: OpenSSLKeyPair?
        do {
            openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password")

            XCTAssertNotNil(openSSLKeyPair)

            var openSSLIdentity: OpenSSLIdentity?
            openSSLIdentity = try OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair!, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "randompassword")
            XCTAssertNotNil(openSSLIdentity)

            let p12Identity = P12Identity(openSSLIdentity: openSSLIdentity!, importPassphrase: "randompassword")


            let ref = Keychain.importP12Identity(p12Identity)
            XCTAssertNotNil(ref)

            let specifier = IdentityImportSpecifier(identityReference: ref!, itemLabel: "SomeLabel")
            Keychain.addIdentity(specifier)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
        

    }



    func clearKeychainItems(type: SecurityClass) {
        var (status, items) = Keychain.keyChainItems(type)
        XCTAssertEqual(status, KeychainStatus.OK)

        var n = items.count
        for item in items {
            status = Keychain.deleteKeyChainItem(itemSpecifier: item.specifier())
            XCTAssertEqual(status, KeychainStatus.OK)

            (status, items) = Keychain.keyChainItems(type)
            XCTAssertEqual(status, KeychainStatus.OK)

            XCTAssertEqual(items.count,n-1)
            n = items.count
        }
        XCTAssertEqual(items.count,0)
    }





}
