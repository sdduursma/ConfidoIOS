//
//  BaseTests.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 14/09/2015.
//

import Foundation
import XCTest
import IOSKeychain


enum TestError : ErrorType {
    case UnknownResourceInBundle, ResourceAccessError
}

public class BaseTests: XCTestCase {
    func testsBundle() -> NSBundle {
        return NSBundle(forClass: self.dynamicType)
    }
    func contentsOfBundleResource(resourceName: String, ofType resourceType: String) throws -> NSData {
        if let path = testsBundle().pathForResource(resourceName, ofType: resourceType) {
            if let data = NSData(contentsOfFile: path) {
                return data
            }
            throw TestError.ResourceAccessError
        }
        throw TestError.UnknownResourceInBundle
    }


    func clearKeychainItems(type: SecurityClass) {
        do {
            var items = try Keychain.keyChainItems(type)

            var n = items.count
            for item in items {
                try Keychain.deleteKeyChainItem(itemDescriptor: item.keychainMatchPropertyValues())

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
