//
//  BufferTests.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 25/09/2015.
//

import Foundation

import XCTest
import ConfidoIOS

class BufferTests: XCTestCase {
    func testBuffer() {
        do {
            var buffer = Buffer<Byte>(size: 4)
            // Buffer should be initialized to zero
            XCTAssertEqual(buffer.values, [0,0,0,0])
            XCTAssertEqual(buffer.elementSize, 1)
            XCTAssertEqual(buffer.byteCount, 4)

            XCTAssertEqual(buffer.hexString,"00000000")


            let raw : [Byte] = [65,66,67,68] // ABCD
            buffer = try Buffer(data: NSData(bytes: raw, length: 4))
            XCTAssertEqual(buffer.values, [65,66,67,68])
            XCTAssertEqual(buffer.base64String, "QUJDRA==")
            XCTAssertEqual(buffer.hexString,"41424344")

            let data = buffer.data
            XCTAssertEqual(data.length, 4)

            buffer.append([1,2])
            XCTAssertEqual(buffer.byteCount, 6)
            XCTAssertEqual(buffer.size, 6)
            XCTAssertEqual(buffer.values, [65,66,67,68,1,2])
        }

        catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testBufferFromHex() {
        do {
            var buffer = try Buffer<Byte>(hexData: "000000")
            XCTAssertEqual(buffer.values, [0,0,0])

            buffer = try Buffer<Byte>(hexData: "0A0B0C")
            XCTAssertEqual(buffer.values, [10,11,12])

            buffer = try Buffer<Byte>(hexData: "0a0b0c")
            XCTAssertEqual(buffer.values, [10,11,12])

            buffer = try Buffer<Byte>(hexData: "f34481ec3cc627bacd5dc3fb08f273e6")
            XCTAssertEqual(buffer.values, [0xf3,0x44,0x81,0xec,0x3c,0xc6,0x27,0xba,0xcd,0x5d,0xc3,0xfb,0x08,0xf2,0x73,0xe6])
            XCTAssertEqual(buffer.hexString, "f34481ec3cc627bacd5dc3fb08f273e6")
        }

        catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }
    }

    func testBufferResizing() {
        var buffer = Buffer<Byte>(size: 4)
        XCTAssertEqual(buffer.values, [0,0,0,0])
        buffer.size = 6
        //Increasing the size will append zeroes
        XCTAssertEqual(buffer.values, [0,0,0,0,0,0])
        buffer.size = 3
        XCTAssertEqual(buffer.values, [0,0,0])

        buffer = Buffer(bytes: [1,2,3,4])
        XCTAssertEqual(buffer.values, [1,2,3,4])
        buffer.size = 6
        XCTAssertEqual(buffer.values, [1,2,3,4,0,0])
        buffer.size = 2
        XCTAssertEqual(buffer.values, [1,2])
    }

    func testBuffer16Bit() {
        do {
            var buffer = Buffer<UInt16>(size: 4)
            // Buffer should be initialized to zero
            XCTAssertEqual(buffer.values, [0,0,0,0])
            XCTAssertEqual(buffer.elementSize, 2)
            XCTAssertEqual(buffer.byteCount, 8)

            let raw : [Byte] = [65,00,66,00,67,00,68,00] // ABCD
            buffer = try Buffer(data: NSData(bytes: raw, length: raw.count))
            XCTAssertEqual(buffer.values, [65,66,67,68])
            let data = buffer.data
            XCTAssertEqual(data.length, 8)

            buffer.size = 6
            XCTAssertEqual(buffer.values, [65,66,67,68,0,0])
            XCTAssertEqual(buffer.byteCount, 12)
            buffer.append([1,2])
            XCTAssertEqual(buffer.byteCount, 16)
            XCTAssertEqual(buffer.values, [65,66,67,68,0,0,1,2])
            XCTAssertEqual(buffer.hexString,"41004200430044000000000001000200")

        }
        catch let error as NSError {
            XCTFail("Unexpected Exception \(error)")
        }

    }
    
    
}
