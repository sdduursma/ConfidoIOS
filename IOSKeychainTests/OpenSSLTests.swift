//
//  OpenSSLTests.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//


import Foundation
import UIKit
import XCTest
import IOSKeychain

class OpenSSLCSRTests: XCTestCase {
    // Check that generateCSRWithPublicKeyData correctly returns an error
    func testCSRWithCorruptDataAndError() {
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        let attributes : [ NSObject : AnyObject] = [ : ]
        do {
            _ = try OpenSSL.generateCSRWithKeyPair(keyPair, csrData: attributes)
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }

    func testCSRWithCorruptDataAndNilError() {
        let attributes : [ NSObject : AnyObject] = [ : ]
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        let csrData = try? OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes)
        XCTAssertNil(csrData)
    }

    func testGenerateCSR() {
        let bundle = NSBundle(forClass: self.dynamicType)
        let keypairData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)
        let attributes : [ NSObject : AnyObject] = [ : ]

        XCTAssertNotNil(keypairData)
        let openSSLKeyPair: OpenSSLKeyPair?
        do {
            openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keypairData, encryptedWithPassword: "password")
            XCTAssertNotNil(openSSLKeyPair)
            XCTAssertNotNil(openSSLKeyPair!.privateKeyData)
            XCTAssertNotNil(openSSLKeyPair!.publicKeyData)
            let csrData = try OpenSSL.generateCSRWithKeyPair(openSSLKeyPair!,csrData: attributes)
            XCTAssertNotNil(csrData)
            let csrString : NSString! = NSString(data: csrData, encoding: NSUTF8StringEncoding)
            XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
            XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
            print("CSR:")
            print(csrString)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testGenerateCSRCorruptData() {
        let attributes : [ NSObject : AnyObject] = [ : ]

        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())
        do {
            _ = try OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes)
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }

        let csrData = try? OpenSSL.generateCSRWithKeyPair(keyPair,csrData: attributes)
        XCTAssertNil(csrData)
    }
}

class OpenSSLKeyPairTests: XCTestCase {

    func testKeyPairFromPEM() {
        let bundle = NSBundle(forClass: self.dynamicType)
        let pemFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(pemFileData)
        let openSSLKeyPair: OpenSSLKeyPair?
        do {
            openSSLKeyPair = try OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "password")
            XCTAssertNotNil(openSSLKeyPair)

        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }


    func testKeyPairWrongPassphrase() {
        let bundle = NSBundle(forClass: self.dynamicType)
        let pemFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(pemFileData)
        do {
            _ = try OpenSSL.keyPairFromPEMData(pemFileData, encryptedWithPassword: "wrongpassword")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testKeyPairCorruptData() {
        let bundle = NSBundle(forClass: self.dynamicType)
        let corruptPEMFileData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1 identity", ofType: "p12")!)

        XCTAssertNotNil(corruptPEMFileData)
        do {
            _ = try OpenSSL.keyPairFromPEMData(corruptPEMFileData, encryptedWithPassword: "wrongpassword")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }
    }
}



class OpenSSLIdentityTests: XCTestCase {
    func testIdentityFromX509File() {
        let bundle = NSBundle(forClass: self.dynamicType)
        let keyPairPEMData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1", ofType: "pem")!)

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData! = NSData(contentsOfFile: bundle.pathForResource("test keypair 1 certificate", ofType: "x509")!)

        XCTAssertNotNil(certificateData)

        do {

            let openSSLKeyPair = try OpenSSL.keyPairFromPEMData(keyPairPEMData, encryptedWithPassword: "password")

            XCTAssertNotNil(openSSLKeyPair)

            let identity = try OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "password")

            XCTAssertNotNil(identity)

            XCTAssertNotNil(identity.p12identityData)
            XCTAssertEqual(identity.friendlyName, "Expend Device ABCD")
        } catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testIdentityFromX509FileCorruptInputs() {
        let keyPairPEMData : NSData = NSData()

        XCTAssertNotNil(keyPairPEMData)

        let certificateData : NSData = NSData()

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: NSData(), publicKeyData: NSData())


        XCTAssertNotNil(openSSLKeyPair)
        do {
            _ = try OpenSSL.pkcs12IdentityWithKeyPair(openSSLKeyPair, certificate: OpenSSLCertificate(certificateData: certificateData), protectedWithPassphrase: "password")
            XCTAssert(false, "Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }

    }


}


