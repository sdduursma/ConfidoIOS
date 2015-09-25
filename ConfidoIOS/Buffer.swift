//
//  Buffer.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 25/09/2015.
//  Copyright © 2015 Curoo Limited. All rights reserved.
//

import Foundation

public typealias Byte = UInt8

public struct ByteBuffer {
    public private(set) var bytes: [Byte]
    public var pointer: UnsafeMutablePointer<Byte> {
        get {
            return UnsafeMutablePointer<Byte>(bytes)
        }
    }
    public init(size: Int) {
        bytes = [Byte](count:size, repeatedValue: 0)
    }
    public init(bytes: [Byte]) {
        self.bytes = bytes
    }
    public init(data: NSData) {
        self.init(size: data.length)
        data.getBytes(&bytes, length:data.length)
    }
    public var data: NSData {
        get { return NSData(bytes: bytes, length: bytes.count) }
    }
    public var base64String: String {
        get { return data.base64EncodedStringWithOptions([]) }
    }
    public var size: Int {
        get {
            return bytes.count
        }
        set {
            if newValue < bytes.count {
                //truncate the buffer to the new size
                bytes = Array(bytes[0..<newValue])
            } else if newValue > bytes.count {
                let newBuffer = [Byte](count:newValue, repeatedValue: 0)
                let existingData = UnsafeMutablePointer<Byte>(bytes)
                let newBufferP = UnsafeMutablePointer<Byte>(newBuffer)
                newBufferP.moveInitializeFrom(existingData, count: bytes.count)
                bytes = newBuffer
            }
        }
    }
}