//
//  BaseTests.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 14/09/2015.
//

import Foundation
import XCTest
import ConfidoIOS


enum TestError : Error {
    case unknownResourceInBundle, resourceAccessError
}

open class BaseTests: XCTestCase {
    func testsBundle() -> Bundle {
        return Bundle(for: type(of: self))
    }
    func contentsOfBundleResource(_ resourceName: String, ofType resourceType: String) throws -> Data {
        if let path = testsBundle().path(forResource: resourceName, ofType: resourceType) {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                return data
            }
            throw TestError.resourceAccessError
        }
        throw TestError.unknownResourceInBundle
    }

    func keychainItems(_ type: SecurityClass) -> [KeychainItem] {
        do {
            return try Keychain.keyChainItems(type)
        } catch {
            return []
        }
    }

    func clearKeychainItems(_ type: SecurityClass) {
        do {
            let items = try Keychain.keyChainItems(type)

            let n = items.count
            print("Deleting \(n) \(type) items from keychain")
            let (successCount, failureCount) = Keychain.deleteAllItemsOfClass(type)
            XCTAssertEqual(items.count,successCount)
            XCTAssertEqual(failureCount,0)
        } catch let error  {
            XCTFail("Unexpected Exception \(error)")
        }
        
    }
}
