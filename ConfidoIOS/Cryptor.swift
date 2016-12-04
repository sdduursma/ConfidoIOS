//
//  Cryptor.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 25/09/2015.

import Foundation
import CommonCrypto



open class Cryptor {
    open class func encrypt<T>(_ inputBuffer: Buffer<T>, key: CryptoKey,
        mode: CipherMode, padding: Padding, initialVector: Buffer<Byte>?) throws -> Buffer<Byte> {
            return try self.operation(UInt32(kCCEncrypt), inputBuffer: inputBuffer,
                key: key, mode: mode, padding: padding, initialVector: initialVector)
    }

    open class func decrypt<T>(_ inputBuffer: Buffer<T>, key: CryptoKey,
        mode: CipherMode, padding: Padding, initialVector: Buffer<Byte>?) throws -> Buffer<Byte> {
            return try self.operation(UInt32(kCCDecrypt), inputBuffer: inputBuffer,
                key: key, mode: mode, padding: padding,initialVector: initialVector)
    }

    class func operation<T>(_ operation: CCOperation, inputBuffer: Buffer<T>, key: CryptoKey,
        mode: CipherMode, padding: Padding, initialVector: Buffer<Byte>?) throws -> Buffer<Byte> {
            if let initialVector = initialVector, initialVector.byteCount != key.keyType.blockSize {
                throw KeychainError.initialVectorMismatch(size: key.keyType.blockSize)
            }
            let algoritm:  CCAlgorithm = UInt32(key.keyType.coreCryptoAlgorithm)
            let options:   CCOptions   = UInt32(padding.rawValue) + UInt32(mode.rawValue)
            let iv                     = initialVector?.voidPointer ?? nil
            var numBytesEncrypted :size_t = 0
            var outputBuffer = Buffer<Byte>(size: inputBuffer.byteCount + key.keyType.blockSize)

            let cryptStatus = CCCrypt(operation,
                algoritm,
                options,
                key.keyMaterial.pointer, key.keyType.keySize,
                iv,
                inputBuffer.pointer, inputBuffer.byteCount,
                outputBuffer.mutablePointer, outputBuffer.byteCount,
                &numBytesEncrypted)

            if UInt32(cryptStatus) == UInt32(kCCSuccess) {
                outputBuffer.size = numBytesEncrypted
                return outputBuffer
            }
            throw KeychainError.cryptoOperationFailed(status: cryptStatus)
    }
}
