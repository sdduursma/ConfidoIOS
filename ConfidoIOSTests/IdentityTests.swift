//
//  IdentityTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 14/09/2015.

import Foundation

import UIKit
import XCTest
import ConfidoIOS

class IdentityTests: BaseTests {


    func testImportPKCS12Identity() {
            clearKeychainItems(.identity)
            clearKeychainItems(.key)
            clearKeychainItems(.certificate)

            let p12Data = try! contentsOfBundleResource("Device Identity", ofType: "p12")

            let transportIdentity = try! KeychainIdentity.importIdentity(p12Data, protectedWithPassphrase: "password", label: "identity")
            let keychainIdentity = try! transportIdentity.addToKeychain()
            XCTAssertEqual(keychainIdentity.certificate!.subject, "Expend Device ABCD")
            XCTAssertEqual(self.keychainItems(.identity).count, 1)
            let keys = self.keychainItems(.key)
            XCTAssertEqual(keys.count,1)
            let storedIdentity = try! KeychainIdentity.identity(IdentityDescriptor(identityLabel: "identity"))
            XCTAssertNotNil(storedIdentity)
            let items = self.keychainItems(.identity)
            XCTAssertEqual(items.count,1)
    }
    
}
