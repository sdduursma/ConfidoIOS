//
//  OpenSSLTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//


import Foundation
import UIKit
import XCTest
import ConfidoIOS
class OpenSSLCSRTests: BaseTests {
    // Check that generateCSRWithPublicKeyData correctly returns an error
    func testCSRWithCorruptDataAndError() {
        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: Data(), publicKeyData: Data())
        let attributes : [AnyHashable: Any] = [ : ]
        do {
            try OpenSSL.generateCSR(withPrivateKeyData: keyPair.privateKeyData, csrData: attributes)
            XCTFail("Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }


    func testGenerateCSR() {
        let keypairData = try! contentsOfBundleResource("test keypair 1", ofType: "pem")
        let attributes : [AnyHashable: Any] = [ : ]

        XCTAssertNotNil(keypairData)
        let openSSLKeyPair: OpenSSLKeyPair?
        openSSLKeyPair = try! OpenSSL.keyPair(fromPEMData: keypairData, encryptedWithPassword: "password")
        XCTAssertNotNil(openSSLKeyPair)
        XCTAssertNotNil(openSSLKeyPair!.privateKeyData)
        XCTAssertNotNil(openSSLKeyPair!.publicKeyData)
        let csrData = try! OpenSSL.generateCSR(withPrivateKeyData: openSSLKeyPair!.privateKeyData as Data,csrData: attributes)
        XCTAssertNotNil(csrData)
        let csrString : NSString! = NSString(data: csrData, encoding: String.Encoding.utf8.rawValue)
        XCTAssert(csrString.hasPrefix("-----BEGIN CERTIFICATE REQUEST-----\n"))
        XCTAssert(csrString.hasSuffix("-----END CERTIFICATE REQUEST-----\n"))
        print("CSR:")
        print(csrString)
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testGenerateCSRCorruptData() {
        let attributes : [AnyHashable: Any] = [ : ]

        let keyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: Data(), publicKeyData: Data())
        do {
            try OpenSSL.generateCSR(withPrivateKeyData: keyPair.privateKeyData,csrData: attributes)
            XCTFail("Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }
}

class OpenSSLKeyPairTests: BaseTests {

    func testKeyPairFromPEM() {
        let pemFileData = try! contentsOfBundleResource("test keypair 1", ofType: "pem")

        let openSSLKeyPair: OpenSSLKeyPair?
        openSSLKeyPair = try! OpenSSL.keyPair(fromPEMData: pemFileData, encryptedWithPassword: "password")
        XCTAssertNotNil(openSSLKeyPair)
    }


    func testKeyPairWrongPassphrase() {
        do {
            let pemFileData = try contentsOfBundleResource("test keypair 1", ofType: "pem")
            try OpenSSL.keyPair(fromPEMData: pemFileData, encryptedWithPassword: "wrongpassword")
            XCTFail("Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }

    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testKeyPairCorruptData() {

        do {
            //Load a P12 file, this is not a PEM, so it will be corrupt.
            let corruptPEMFileData = try contentsOfBundleResource("Device Identity", ofType: "p12")
            XCTAssertNotNil(corruptPEMFileData)
            try OpenSSL.keyPair(fromPEMData: corruptPEMFileData, encryptedWithPassword: "wrongpassword")
            XCTFail("Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9997)
            XCTAssertEqual(error.localizedDescription,"Invalid Private Key in PEM File or Incorrect Passphrase")
        }
    }
}



class OpenSSLIdentityTests: BaseTests {
    func testIdentityFromX509File() {
        let keyPairPEMData = try! contentsOfBundleResource("test keypair 1", ofType: "pem")

        let certificateData = try! contentsOfBundleResource("test keypair 1 certificate", ofType: "x509")

        XCTAssertNotNil(certificateData)


        let openSSLKeyPair = try! OpenSSL.keyPair(fromPEMData: keyPairPEMData, encryptedWithPassword: "password")

        XCTAssertNotNil(openSSLKeyPair)

        let identity = try! OpenSSL.pkcs12Identity(withPrivateKeyData: openSSLKeyPair.privateKeyData, certificateData: certificateData, protectedWithPassphrase: "password")


        XCTAssertNotNil(identity)

        XCTAssertNotNil(identity.p12identityData)
        XCTAssertEqual(identity.friendlyName, "Expend Device ABCD")
    }

    // These tests are not exhaustive. There are many paths through the code and ideally there should be tests for every combination of input.

    func testIdentityFromX509FileCorruptInputs() {
        let keyPairPEMData = Data()

        XCTAssertNotNil(keyPairPEMData)

        let certificateData = Data()

        XCTAssertNotNil(certificateData)

        let openSSLKeyPair = OpenSSLRSAKeyPair(keyLength: 2048, privateKeyData: Data(), publicKeyData: Data())


        XCTAssertNotNil(openSSLKeyPair)
        do {
            _ = try OpenSSL.pkcs12Identity(withPrivateKeyData: openSSLKeyPair.privateKeyData, certificateData: certificateData, protectedWithPassphrase: "password")
            XCTFail("Exception should have been raised")
        } catch let error as NSError {
            XCTAssertEqual(error.code, 9999)
            XCTAssertEqual(error.localizedDescription,"Internal Error")
        }
    }
}


