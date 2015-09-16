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

let customCACertName = "Curoo Limited Certification Authority RSA Root Certificate"
let levelOneCAName   = "Curoo Limited Product Development Authority RSA Root Certificate"
let levelTwoCAName   = "Expend Product Development Authority RSA Root Certificate"
let finalPinnedCAName    = "Expend Development Device Identity Authority RSA Certificate"

class CertificateTests: BaseTests {
    func testCertificateFromCERFile() {
        do {
            self.clearKeychainItems(.Certificate)
            let certificateDERData = try contentsOfBundleResource(finalPinnedCAName, ofType: "cer")
            let transportCertificate = try KeychainCertificate.certificate(certificateDERData, certificateType: .RootCACertificate)
            XCTAssertEqual(transportCertificate.subject, finalPinnedCAName)

            let certificate = try transportCertificate.addToKeychain()
            XCTAssertEqual(certificate.subject, finalPinnedCAName)
            XCTAssertNotNil(certificate.secCertificate)
            XCTAssertEqual(self.keychainItems(.Certificate).count,1)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func bundledCertificate(filename: String, certificateType: CertificateType) throws -> TransportCertificate {
        let certificateDERData = try contentsOfBundleResource(filename, ofType: "cer")
        return try KeychainCertificate.certificate(certificateDERData, certificateType: certificateType)
    }

    func testTrustedCertificateChain() {
        do {
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate(customCACertName, certificateType: .RootCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)
            try trustAnchor.addCertificate(try bundledCertificate(levelOneCAName, certificateType: .IntermediateCACertificate), evaluateTrust : true)
            try trustAnchor.addCertificate(try bundledCertificate(levelTwoCAName, certificateType: .IntermediateCACertificate), evaluateTrust : true)
            try trustAnchor.addCertificate(try bundledCertificate(finalPinnedCAName, certificateType: .IntermediateCACertificate), evaluateTrust : true)
            XCTAssertEqual(trustAnchor.certificates.count, 4)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }
    func testEvaluateTrustForClientCertificate() {
        do {
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate(finalPinnedCAName, certificateType: .RootCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)
            try trustAnchor.addCertificate(try bundledCertificate(levelOneCAName, certificateType: .IntermediateCACertificate))
            try trustAnchor.addCertificate(try bundledCertificate(levelTwoCAName, certificateType: .IntermediateCACertificate))
            try trustAnchor.addCertificate(try bundledCertificate(finalPinnedCAName, certificateType: .IntermediateCACertificate))

            let p12Data = try contentsOfBundleResource("Device Identity", ofType: "p12")

            let transportIdentity = try KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")

            let trustPoint = try trustAnchor.trustPoint(transportIdentity.secTrust)

            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Unspecified)


            XCTAssertEqual(trustAnchor.certificates.count, 4)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testEvaluateTrustForClientCertificateRootAnchor() {
        do {
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate(finalPinnedCAName, certificateType: .RootCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)

            let CPCA = try bundledCertificate(levelOneCAName, certificateType: .IntermediateCACertificate)
            let ECA  = try bundledCertificate(levelTwoCAName, certificateType: .IntermediateCACertificate)
            let EDCA = try bundledCertificate(finalPinnedCAName, certificateType: .IntermediateCACertificate)
            let deviceCert = try bundledCertificate("test keypair 1 certificate", certificateType: .Unknown)

            let trust = try deviceCert.trust([EDCA,ECA,CPCA,rootCertificate], policies: nil)
            let trustPoint = try trustAnchor.trustPoint(trust)

            let trustResult = try trustPoint.evaluateTrust()
            trustPoint.getTrustProperties()
            XCTAssertEqual(trustResult, TrustResult.Unspecified)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testRealCertificateAgainstCustomRootCAAnchor() {
        do {
            /*
            Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor
            */

            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate(finalPinnedCAName, certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)
            let appleCert = try bundledCertificate("www.apple.com", certificateType: .ServerSSLCertificate)
            let intermediary = try bundledCertificate("Symantec Class 3 EV SSL CA - G3", certificateType: .IntermediateCACertificate)
            // It seems as if you need to pass all the intermediary certificates as well...
            let trust = try appleCert.trust([intermediary], policies: [SecPolicyCreateSSL(false, "www.apple.com")])
            let trustPoint = try trustAnchor.trustPoint(trust)
            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Deny)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }


    func testRealCertificateAgainstDifferentRootCAAnchor() {
        do {
            /*
            Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor
            */

            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)
            let appleCert = try bundledCertificate("www.apple.com", certificateType: .ServerSSLCertificate)
            let intermediary = try bundledCertificate("Symantec Class 3 EV SSL CA - G3", certificateType: .IntermediateCACertificate)
            // It seems as if you need to pass all the intermediary certificates as well...
            let trust = try appleCert.trust([intermediary], policies: [SecPolicyCreateSSL(false, "www.apple.com")])
            let trustPoint = try trustAnchor.trustPoint(trust)
            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Deny)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }



    func testRealCertificateChainAnchored() {
        do {
            self.clearKeychainItems(.Certificate)
            let anchorCertificate = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: anchorCertificate)
            let googleCert = try bundledCertificate("www.google.co.uk", certificateType: .ServerSSLCertificate)
            let googleTrust = try trustAnchor.trustPoint(googleCert)
            let trustResult = try googleTrust.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Unspecified)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testRealCertificateChainDifferentChainAnchor() {
        do {
            self.clearKeychainItems(.Certificate)
            let anchorCertificate = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: anchorCertificate)

            let appleCert = try bundledCertificate("www.apple.com", certificateType: .ServerSSLCertificate)
            let intermediary = try bundledCertificate("Symantec Class 3 EV SSL CA - G3", certificateType: .IntermediateCACertificate)
            // It seems as if you need to pass all the intermediary certificates as well...
            let trust = try appleCert.trust([intermediary], policies: nil)
            let trustPoint = try trustAnchor.trustPoint(trust)
            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Deny)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }


    func testRealCertificateChainUntrustuedRoot() {
        do {
            /*
            This test simulates a TrustError by using an empty TrustPoint
            This way, we can simulate the "Root certificate is not trusted" error and that is correct
            */
            self.clearKeychainItems(.Certificate)
            let trustAnchor = TrustAnchorPoint()
            let intermediaryCert = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let googleCert = try bundledCertificate("www.google.co.uk", certificateType: .ServerSSLCertificate)
            let trust = try googleCert.trust([intermediaryCert], policies: nil)
            let googleTrustPoint = try trustAnchor.trustPoint(trust)
            let trustResult = try googleTrustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Deny)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }

    }

    func testRealCertificateChainUntrustuedAnchoredRoot() {
        do {
            /*
            This test simulates a TrustError by using an empty TrustPoint
            This way, we can simulate the "Root certificate is not trusted" error and that is correct
            */
            self.clearKeychainItems(.Certificate)
            let intermediaryCert = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: intermediaryCert)
            let googleCert = try bundledCertificate("www.google.co.uk", certificateType: .ServerSSLCertificate)
            let trust = try googleCert.trust([], policies: nil)
            let googleTrustPoint = try trustAnchor.trustPoint(trust)
            let trustResult = try googleTrustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Unspecified)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }

    func testRealCertificateUnanchored() {
        do {
            // We are setting the anchor to the Google CA, so the Apple certificate cannot be validated
            self.clearKeychainItems(.Certificate)
            let appleCert = try bundledCertificate("www.apple.com", certificateType: .ServerSSLCertificate)
            let intermediary = try bundledCertificate("Symantec Class 3 EV SSL CA - G3", certificateType: .IntermediateCACertificate)
            // It seems as if you need to pass all the intermediary certificates as well...
            let trust = try appleCert.trust([intermediary], policies: nil)
            let appleTrust = try TrustPoint(secTrust: trust, certificate: appleCert)
            let trustResult = try appleTrust.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Unspecified)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testRealCertificateNotMatchingAnchor() {
        do {
            // We are setting the anchor to the Google CA, so the Apple certificate cannot be validated
            self.clearKeychainItems(.Certificate)
            let rootCertificate = try bundledCertificate("Google Internet Authority G2", certificateType: .IntermediateCACertificate)
            let trustAnchor = TrustAnchorPoint(anchorCertificate: rootCertificate)
            let appleCert = try bundledCertificate("www.apple.com", certificateType: .ServerSSLCertificate)
            let trustPoint = try trustAnchor.trustPoint(appleCert)
            let trustResult = try trustPoint.evaluateTrust()
            XCTAssertEqual(trustResult, TrustResult.Deny)

        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
    }
    
    
}