//
//  CertificateTests.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation

import UIKit
import XCTest
import IOSKeychain

class CertificateTests: BaseTests {

    func testCertificateFromCERFile() {
        do {
            self.clearKeychainItems(.Certificate)
            let certificateDERData = try contentsOfBundleResource("Curoo Root CA", ofType: "cer")

            let transportCertificate = try KeychainCertificate.certificate(certificateDERData)
            XCTAssertEqual(transportCertificate.subject, "Curoo Limited Certification Authority")

            let certificate = try transportCertificate.addToKeychain()
            XCTAssertEqual(certificate.subject, "Curoo Limited Certification Authority")
            XCTAssertNotNil(certificate.secCertificate)
            XCTAssertEqual(self.keychainItems(.Certificate).count,1)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func bundledCertificate(filename: String) throws -> TransportCertificate {
        let certificateDERData = try contentsOfBundleResource(filename, ofType: "cer")
        return try KeychainCertificate.certificate(certificateDERData)
    }

    func testTrustedCertificateChain() {
        do {
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate("Curoo Root CA")
            let trustChain = CertificateTrustChain(anchorCertificate: rootCertificate)
            try trustChain.addCertificate(try bundledCertificate("Curoo Product CA"))
            try trustChain.addCertificate(try bundledCertificate("Expend CA"))
            try trustChain.addCertificate(try bundledCertificate("Expend Device CA"))
            XCTAssertEqual(trustChain.certificates.count, 4)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testEvaluateTrustForClientCertificate() {
        do {
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate("Curoo Root CA")
            let trustChain = CertificateTrustChain(anchorCertificate: rootCertificate)
            try trustChain.addCertificate(try bundledCertificate("Curoo Product CA"))
            try trustChain.addCertificate(try bundledCertificate("Expend CA"))
            try trustChain.addCertificate(try bundledCertificate("Expend Device CA"))

            let p12Data = try contentsOfBundleResource("Device Identity", ofType: "p12")

            let transportIdentity = try KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")

            let trustPoint = try trustChain.trustEvaluationPoint(transportIdentity.secTrust)

            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Proceed)

            
            XCTAssertEqual(trustChain.certificates.count, 4)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

}