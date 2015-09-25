//
//  ByteBufferTests.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 25/09/2015.
//

import Foundation

import UIKit
import XCTest
import ConfidoIOS

class ByteBufferTests: XCTestCase {


    func testBuffer() {
        var buffer = ByteBuffer(size: 4)
        // Buffer should be initialized to zero
        XCTAssertEqual(buffer.bytes, [0,0,0,0])

        let raw : [Byte] = [65,66,67,68] // ABCD
        buffer = ByteBuffer(data: NSData(bytes: raw, length: 4))
        XCTAssertEqual(buffer.bytes, [65,66,67,68])
        XCTAssertEqual(buffer.base64String, "QUJDRA==")
        let data = buffer.data
        XCTAssertEqual(data.length, 4)
    }


    func testBufferResizing() {
        var buffer = ByteBuffer(size: 4)
        XCTAssertEqual(buffer.bytes, [0,0,0,0])
        buffer.size = 6
        //Increasing the size will append zeroes
        XCTAssertEqual(buffer.bytes, [0,0,0,0,0,0])
        buffer.size = 3
        XCTAssertEqual(buffer.bytes, [0,0,0])

        buffer = ByteBuffer(bytes: [1,2,3,4])
        XCTAssertEqual(buffer.bytes, [1,2,3,4])
        buffer.size = 6
        XCTAssertEqual(buffer.bytes, [1,2,3,4,0,0])
        buffer.size = 2
        XCTAssertEqual(buffer.bytes, [1,2])
    }

}
