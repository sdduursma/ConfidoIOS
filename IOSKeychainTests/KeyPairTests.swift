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
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keyPairSpecifier = PermanentKeychainKeyPairProperties(keyType: .RSA, keySize: 1024, keyLabel: "AAA", keyAppTag: "BBB", keyAppLabel: "CCC")
            var keyPair : KeychainKeyPair?
            keyPair = try Keychain.generateKeyPair(keyPairSpecifier)
            XCTAssertNotNil(keyPair)

            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            let keyQuery = KeychainKeyProperties(keyLabel: "AAA")
            var keyItem: KeychainItem?
            keyItem = try Keychain.fetchMatchingItem(thatMatchesProperties: keyQuery)
            XCTAssertNotNil(keyItem)

            XCTAssertEqual(keyPair!.privateKey.keyType, KeyType.RSA)
            XCTAssertEqual(keyPair!.publicKey.keyType, KeyType.RSA)


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

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }


    }

    func testGenerateUnnamedKeyPair() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keyPairSpecifier = TemporaryKeychainKeyPairProperties(keyType: .RSA, keySize: 1024)
            let keyPair = try Keychain.generateKeyPair(keyPairSpecifier)
            XCTAssertNotNil(keyPair)

            items =  try Keychain.keyChainItems(.Key)
            // Temporary keys are not stored in the keychain
            XCTAssertEqual(items.count,0)

            XCTAssertEqual(keyPair!.privateKey.keySize, 1024)
            XCTAssertEqual(keyPair!.publicKey.keySize, 1024)


            // There is no way to extract the data of a key for non-permanent keys
            let publicKeyData = keyPair!.publicKey.keyData
            XCTAssertNil(publicKeyData)

            let privateKeyData = keyPair!.privateKey.keyData
            XCTAssertNil(privateKeyData)
        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testDuplicateKeyPairMatching() {
        do {
            clearKeychainItems(.Key)
            var items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            var keyPairSpecifier = PermanentKeychainKeyPairProperties(keyType: .RSA, keySize: 1024, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
            var keyPair : KeychainKeyPair? = try Keychain.generateKeyPair(keyPairSpecifier)
            XCTAssertNotNil(keyPair)


            items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,2)

            // Test that labels make the keypair unique
            keyPair = try Keychain.generateKeyPair(keyPairSpecifier)

            // keySize, keyLabel, keyAppTag, keyAppLabel all the same --> DuplicateItemError
//TODO:    XCTAssertEqual(status, KeychainStatus.DuplicateItemError)
            XCTAssertNil(keyPair)

            // different keySize
            keyPairSpecifier = PermanentKeychainKeyPairProperties(keyType: .RSA, keySize: 2048, keyLabel: "A1", keyAppTag: "BBB", keyAppLabel: "CCC")
            keyPair = try Keychain.generateKeyPair(keyPairSpecifier)
            XCTAssertNotNil(keyPair)
        } catch let error {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }

    func testExportCSR (){
        do {
            clearKeychainItems(.Key)
            let items = try Keychain.keyChainItems(SecurityClass.Key)
            XCTAssertEqual(items.count,0)

            let keyPairSpecifier = PermanentKeychainKeyPairProperties(keyType: .RSA, keySize: 1024, keyLabel: "KeyPair1")
            let keyPair : KeychainKeyPair? = try Keychain.generateKeyPair(keyPairSpecifier)
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
        } catch let error{
            XCTFail("Unexpected Exception \(error)")
        }
        
    }

    func testImportPEMKey() {
        do {
            clearKeychainItems(.Key)
            let items = try Keychain.keyChainItems(.Key)
            XCTAssertEqual(items.count,0)
            let bundle = NSBundle(forClass: self.dynamicType)
            let keyPairPEMData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

            XCTAssertNotNil(keyPairPEMData)
            let detachedKeyPair = try KeychainKeyPair.importKeyPair(pemEncodedData: keyPairPEMData, encryptedWithPassphrase: "password", keyLabel: "abcd")

            let keyPair = try detachedKeyPair.addToKeychain()

            XCTAssertNotNil(keyPair)
            XCTAssertEqual(keyPair!.privateKey.itemLabel, "abcd")

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
            
            
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

//        do {
//
//            //            let openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password")
//            //
//            //            XCTAssertNotNil(openSSLKeyPair)
//            //
//            //            var openSSLIdentity: OpenSSLIdentity?
//            //            openSSLIdentity = try OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair!, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "randompassword")
//            //            XCTAssertNotNil(openSSLIdentity)
//            //
//            //            let p12Identity = P12Identity(openSSLIdentity: openSSLIdentity!, importPassphrase: "randompassword")
//            //
//            //
//            //            let ref = Keychain.importP12Identity(p12Identity)
//            //            XCTAssertNotNil(ref)
//            //
//            //            let specifier = IdentityImportSpecifier(identityReference: ref!, itemLabel: "SomeLabel")
//            //            Keychain.addIdentity(specifier)
//
//        } catch let error  {
//            XCTFail("Unexpected Exception \(error)")
//        }
//        

        }
    
    
    
    func clearKeychainItems(type: SecurityClass) {
        do {
            var items = try Keychain.keyChainItems(type)

            var n = items.count
            for item in items {
                try Keychain.deleteKeyChainItem(itemSpecifier: item.keychainMatchPropertyValues())

                items = try Keychain.keyChainItems(type)

                XCTAssertEqual(items.count,n-1)
                n = items.count
            }
            XCTAssertEqual(items.count,0)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }


    
    
    
}
