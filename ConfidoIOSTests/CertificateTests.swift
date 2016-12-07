//
//  CertificateTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation

import UIKit
import XCTest
import ConfidoIOS

let kCustomCACertificateName      = "Custom Root CA"
let kLevelOneCACertificateName    = "Custom Level 2 CA"
let kLevelTwoCACertificateName    = "Custom Level 3 CA"
let kFinalPinnedCACertificateName = "Final Level 4 Issuing CA"
let kFinalPinnedCASubject         = "Expend Development Device Identity Authority RSA Certificate"

//TODO: Lock the evaluation date to... today to prevent future failures
//TODO: TrustEvaluationPoints (TrustManager)

class CertificateTests: BaseTests {

    func rootAnchor() throws -> TrustAnchor  {
        let rootCertificate = try bundledCertificate(kCustomCACertificateName)
        return TrustAnchor(anchorCertificate: rootCertificate, name: "RootCA")
    }

    func level1CustomCA() throws -> TrustAnchor {
        let certificate = try bundledCertificate(kLevelOneCACertificateName)
        let parentAnchor = try rootAnchor()
        return try parentAnchor.extendAnchor(certificate, name: "Level 1 CA")
    }

    func level2CustomCA() throws -> TrustAnchor {
        let certificate = try bundledCertificate(kLevelTwoCACertificateName)
        let parentAnchor = try level1CustomCA()

        return try parentAnchor.extendAnchor(certificate, name: "Level 2 CA")
    }

    func level3IssuerCA() throws -> TrustAnchor {
        return try level2CustomCA().extendAnchor(
            try bundledCertificate(kFinalPinnedCACertificateName),
            name: "Issuing CA")
    }

    func appleCert() throws -> Certificate {
        return try bundledCertificate("www.apple.com")
    }

    func symantecRealCert() throws -> Certificate {
        return try bundledCertificate("Symantec Class 3 EV SSL CA - G3")
    }

    func googleRealCACert() throws -> Certificate {
        return try bundledCertificate("Google Internet Authority G2")
    }

    func googleCAAnchor() throws -> TrustAnchor {
        return try TrustAnchor(anchorCertificate: googleRealCACert(), name: "Google CA")
    }

    func googleCert() throws -> Certificate {
        return try bundledCertificate("www.google.co.uk")
    }

    func customPinnedAnchorOnly() throws -> TrustAnchor {
        return TrustAnchor(anchorCertificate: try bundledCertificate(kFinalPinnedCACertificateName))
    }


    func testCertificateFromCERFileWithLabel() {
        self.clearKeychainItems(.certificate)
        let certificateDERData = try! contentsOfBundleResource(kFinalPinnedCACertificateName, ofType: "cer")
        let transportCertificate = try! KeychainCertificate.certificate(certificateDERData, itemLabel: "certificate")
        XCTAssertEqual(transportCertificate.subject, kFinalPinnedCASubject)

        let certificate = try! transportCertificate.addToKeychain()
        XCTAssertNotNil(certificate)

        XCTAssertEqual(certificate!.subject, kFinalPinnedCASubject)
        XCTAssertNotNil(certificate!.secCertificate)
        XCTAssertEqual(self.keychainItems(.certificate).count,1)

        let storedCertificate = try! KeychainCertificate.findInKeychain(CertificateDescriptor(certificateLabel: "certificate"))
        XCTAssertNotNil(storedCertificate)
    }

    func testCertificateFromCERFileWithoutLabel() {
        self.clearKeychainItems(.certificate)
        let certificateDERData = try! contentsOfBundleResource(kFinalPinnedCACertificateName, ofType: "cer")
        let transportCertificate = try! KeychainCertificate.certificate(certificateDERData)
        XCTAssertEqual(transportCertificate.subject, kFinalPinnedCASubject)

        let certificate = try! transportCertificate.addToKeychain()
        XCTAssertNil(certificate) // The certificate does not have label, so we can't get a reference this way
        let items = self.keychainItems(.certificate)

        XCTAssertEqual(items.count,1)
        let actualCertificate = items[0] as! KeychainCertificate

        let storedCertificate = try! KeychainCertificate.findInKeychain(CertificateDescriptor(certificateLabel: actualCertificate.subject))
        XCTAssertNotNil(storedCertificate)
    }


    func bundledCertificate(_ filename: String) throws -> TransportCertificate {
        let certificateDERData = try contentsOfBundleResource(filename, ofType: "cer")
        return try KeychainCertificate.certificate(certificateDERData)
    }

    func testCertificateTrustAnchorChain()  {
        let rootCAAnchor   = try! rootAnchor()
        XCTAssertEqual(rootCAAnchor.certificateChain.count, 1)

        let level1CAAnchor = try! level1CustomCA()
        XCTAssertEqual(level1CAAnchor.certificateChain.count, 2)

        let level2CAAnchor = try! level2CustomCA()
        XCTAssertEqual(level2CAAnchor.certificateChain.count, 3)

        let level3CAAnchor = try! level3IssuerCA()
        XCTAssertEqual(level3CAAnchor.certificateChain.count, 4)
    }

    func testEvaluateTrustForClientCertificate()  {
        self.clearKeychainItems(.certificate)

        let p12Data = try! contentsOfBundleResource("Device Identity", ofType: "p12")
        let transportIdentity = try! KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")
        let trustPoint = try! CertificateTrustPoint(secTrust: transportIdentity.secTrust)

        //Evaluate against the Root CA, with missing intermediaries
        var result = try! trustPoint.evaluateTrust(rootAnchor())
        XCTAssertEqual(result, TrustResult.deny)

        //Evaluate against the Issuer
        result = try! trustPoint.evaluateTrust(level3IssuerCA())
        XCTAssertEqual(result, TrustResult.unspecified)
    }

    func testEvaluateTrustForClientCertificatePinnedAtRoot() {
        let deviceCert = try! bundledCertificate("test keypair 1 certificate")

        let trustNoAdditionalCerts = try! deviceCert.trustPoint(.sslClient(name: nil), additionalCertificates:[] )
        let trustAllCerts          = try! deviceCert.trustPoint(.sslClient(name: nil),
            additionalCertificates:[
                level3IssuerCA().anchorCertificate,
                level2CustomCA().anchorCertificate,
                level1CustomCA().anchorCertificate
            ] )

        var result = try! trustNoAdditionalCerts.evaluateTrust(rootAnchor())
        XCTAssertEqual(result, TrustResult.deny)

        result = try! trustAllCerts.evaluateTrust(rootAnchor())
        XCTAssertEqual(result, TrustResult.unspecified)
    }

    func testRealCertificateAgainstCustomRootCAAnchor() {
        /*
        Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor
        */
        let trust = try! appleCert().trustPoint(TrustPolicy.sslServer(hostname: nil),
            additionalCertificates: [symantecRealCert()])

        var result = try! trust.evaluateTrust() // This should be allowed because we are checking a real certificate
        XCTAssertEqual(result, TrustResult.unspecified)

        result = try! trust.evaluateTrust(rootAnchor())
        XCTAssertEqual(result, TrustResult.deny)
    }


    func testRealCertificateAgainstDifferentRootCAAnchor() {
        /*
        Tests that the policies reject a real certificate (valid under ordinary circumstances) against a pinned anchor (also real)
        */
        let trust = try! appleCert().trustPoint(TrustPolicy.sslServer(hostname: nil),
            additionalCertificates: [symantecRealCert()])
        let result = try! trust.evaluateTrust(googleCAAnchor())
        XCTAssertEqual(result, TrustResult.deny)
    }


    func testRealCertificateChainAnchored() {
        let trust = try! googleCert().trustPoint(TrustPolicy.sslServer(hostname: nil),
            additionalCertificates: [])
        
        let result = try! trust.evaluateTrust(googleCAAnchor())
        XCTAssertEqual(result, TrustResult.unspecified)
    }
    
}
