//
//  CryptoKey.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 27/09/2015.
//

import Foundation
import Security
import CommonCrypto


public enum CryptoError : Error, CustomStringConvertible {
    case noKeyFound
    case kvcMismatch(expected: [Byte], got: [Byte])
    case keySizeMismatch(expected: Int, got: Int)


    public var description: String {
        switch self {
        case .noKeyFound:
            return "NoKeyFound"
        case .kvcMismatch(let expected, let got):
            return "Key KVC mismatch expected [\(expected)] got [\(got)]"
        case .keySizeMismatch(let expected, let got):
            return "Key length mismatch expected [\(expected)]  bytes got [\(got)] bytes"
        }
    }
}


public enum DESKeyLength : UInt8 {
    case des1 = 8
    case des3 = 24
    var byteCount: UInt8 {
        get {
            return self.rawValue / 8 * 8
        }
    }
    var bitCount: Int {
        get {
            return Int(self.rawValue) * 8
        }
    }

}
public enum AESKeyLength : UInt8 {
    case aes128 = 16
    case aes192 = 24
    case aes256 = 32
    var byteCount: UInt8 {
        get {
            return self.rawValue
        }
    }
    var bitCount: Int {
        get {
            return Int(self.rawValue) * 8
        }
    }
}

public let kCryptorAESKeyType : Byte = 1
public let kCryptorDESKeyType : Byte = 2

public let kKeyCheckValueByteCount : Byte = 3

public enum CryptoKeyType : CustomStringConvertible {
    case aes(keyLength: AESKeyLength)
    case des(keyLength: DESKeyLength)
    public init?(keyTypeCode: Byte, keyLength: Byte) {
        switch keyTypeCode {
        case kCryptorAESKeyType:
            switch keyLength {
            case 16: self = .aes(keyLength: .aes128)
            case 24: self = .aes(keyLength: .aes192)
            case 32: self = .aes(keyLength: .aes256)
            default: return nil
            }
        case kCryptorDESKeyType:
            switch keyLength {
            case 7:  self = .des(keyLength: .des1)
            case 21: self = .des(keyLength: .des3)
            default: return nil
            }
        default: return nil
        }
    }

    public var rawValue: [Byte] {
        switch self {
        case .aes(let keyLength): return [kCryptorAESKeyType,keyLength.rawValue]
        case .des(let keyLength): return [kCryptorDESKeyType,keyLength.rawValue]
        }
    }

    public var description: String {
        switch self {
        case .aes(let keyLength): return "AES-\(keyLength)"
        case .des(let keyLength) where keyLength == DESKeyLength.des1:   return "DES"
        case .des(let keyLength) where keyLength == DESKeyLength.des3:   return "3DES"
        default: return "-"
        }
    }
    public var keySize: Int {
        switch self {
        case .aes(let keyLength): return Int(keyLength.byteCount)
        case .des(let keyLength): return Int(keyLength.byteCount)
        }
    }
    public var coreCryptoAlgorithm: Int {
        switch self {
        case .aes( _): return kCCAlgorithmAES
        case .des(let keyLength) where keyLength == DESKeyLength.des1: return kCCAlgorithmDES
        case .des(let keyLength) where keyLength == DESKeyLength.des3: return kCCAlgorithm3DES
        default: assertionFailure("Logic error - this code should not be called"); return 0
        }
    }
    public var blockSize: Int {
        switch self {
        case .aes( _): return kCCBlockSizeAES128
        case .des(let keyLength) where keyLength == DESKeyLength.des1: return kCCBlockSizeDES
        case .des(let keyLength) where keyLength == DESKeyLength.des3: return kCCBlockSize3DES
        default: assertionFailure("Logic error - this code should not be called"); return 0
        }
    }
}

public enum CipherMode : RawRepresentable {
    case ecb, cbc
    public init?(rawValue: Int) {
        switch rawValue {
        case kCCOptionECBMode:  self = .ecb
        case 0:                 self = .cbc
        default: return nil
        }
    }
    public var rawValue: Int {
        switch self {
        case .ecb:  return kCCOptionECBMode
        case .cbc:  return 0
        }
    }
}

public enum Padding : RawRepresentable {
    case none, pkcs7
    public init?(rawValue: Int) {
        switch rawValue {
        case 0: self = .none
        case kCCOptionPKCS7Padding: self = .pkcs7
        default: return nil
        }
    }
    public var rawValue: Int {
        switch self {
        case .none:  return 0
        case .pkcs7: return kCCOptionPKCS7Padding
        }
    }
}

public func generateRandomBytes(_ size: Int) -> ByteBuffer {
    do {
        let keyBuffer = ByteBuffer(size: size)
        try secEnsureOK(SecRandomCopyBytes(kSecRandomDefault, size, keyBuffer.mutablePointer))
        return keyBuffer
    }
    catch {
        assertionFailure("Could not generate random bytes")
        return ByteBuffer()
    }
}


open class KeyStorageWrapper {
    /**
    Returns a raw, storable representation of the key material
    The buffer stores (1) The type of Key, (2) A Key Check Value (KCV) (3) the actual cryptographic key
    */
    open class func wrap(_ key: CryptoKey) -> ByteBuffer {
        var buffer = ByteBuffer()
        buffer.append(key.keyType.rawValue)             // Type and length of Key (Two bytes)
        buffer.append(key.keyMaterial.values)
        buffer.append([kKeyCheckValueByteCount])        // Length of KCV
        buffer.append(key.keyCheckValue)
        return buffer
    }

    open class func unwrap(_ buffer: ByteBuffer) throws -> CryptoKey {
        if let keyType = CryptoKeyType.init(keyTypeCode: buffer.values[0], keyLength: buffer.values[1]) {
            var startIndex  = buffer.values.startIndex
            startIndex = startIndex.advanced(by: 2) // Skip keyTypeCode, keyLength
            var endIndex = startIndex.advanced(by: Int(buffer.values[1]))
            let keyData = buffer.values[startIndex..<endIndex]
            let kvcLength = buffer.values[endIndex]
            if kvcLength != kKeyCheckValueByteCount {
                //TODO: Raise Error
            }
            startIndex = endIndex.advanced(by: 1)
            endIndex = startIndex.advanced(by: Int(kvcLength))

            let kvcData = buffer.values[startIndex..<endIndex]
            let key = try CryptoKey(keyType: keyType, keyData: Array(keyData))
            if key.keyCheckValue == Array(kvcData) {
                return key
            }
            throw CryptoError.kvcMismatch(expected: Array(kvcData), got: key.keyCheckValue)
        }
        throw CryptoError.noKeyFound
    }
}

public let kNumberOfRounds : UInt32 = 20000


public func PBKDFDeriveKey(_ passphrase: String, salt: String, rounds: UInt32, size: Int, algorithm : UInt32 = UInt32(kCCPRFHmacAlgSHA1)) -> ByteBuffer! {
    do {
        let utf8data = passphrase.data(using: String.Encoding.utf8)
        let buffer = try ByteBuffer(data: utf8data!)
        let utf8salt = salt.data(using: String.Encoding.utf8)
        let saltBuffer = try ByteBuffer(data: utf8salt!)
        return PBKDFDeriveKey(buffer, salt: saltBuffer, rounds: rounds, size: size, algorithm: algorithm)
    } catch {
        return nil
    }

}
public func PBKDFDeriveKey(_ buffer: ByteBuffer, salt: ByteBuffer, rounds: UInt32, size: Int, algorithm : UInt32 = UInt32(kCCPRFHmacAlgSHA1)) -> ByteBuffer! {
    do {
        return try buffer.pointer.withMemoryRebound(to: Int8.self, capacity: 1) { int8BufferPointer in
            let derivedKeyBuffer = ByteBuffer(size: size)
            try secEnsureOK(CCKeyDerivationPBKDF(UInt32(kCCPBKDF2), int8BufferPointer, buffer.byteCount,
                                                 salt.mutablePointer, salt.byteCount, algorithm, rounds,
                                                 derivedKeyBuffer.mutablePointer, derivedKeyBuffer.byteCount))
            return derivedKeyBuffer
        }
    } catch {
        return nil
    }
}

public struct CryptoKey {
    public let keyType:  CryptoKeyType
    let keyMaterial:     ByteBuffer
    var keyCheckValue:   [Byte] = []

    public init(keyType: CryptoKeyType) {
        self.keyType = keyType
        self.keyMaterial = ByteBuffer(bytes: generateRandomBytes(keyType.keySize).values)
        self.keyCheckValue = makeCheckValue()
    }

    public init(keyType: CryptoKeyType, hexKeyData: String) throws {
        self.keyType = keyType
        if hexKeyData.characters.count != keyType.keySize * 2 {
            throw KeychainError.dataExceedsBlockSize(size: keyType.keySize * 2)
        }
        try self.keyMaterial = ByteBuffer(hexData: hexKeyData)
        self.keyCheckValue = makeCheckValue()
    }

    public init(keyType: CryptoKeyType, keyData: [Byte]) throws {
        self.keyType = keyType
        if keyData.count != keyType.keySize {
            throw CryptoError.keySizeMismatch(expected: keyType.keySize, got: keyData.count)
        }

        self.keyMaterial = ByteBuffer(bytes: keyData)
        self.keyCheckValue = makeCheckValue()
    }

    //Derives an AES128 key from a passphrase and salt using n rounds with PBKDF and HMAC-SHA1
    //See http://robnapier.net/aes-commoncrypto
    public init(deriveKeyFromPassphrase passphrase: String, salt: String, n rounds: UInt32 = kNumberOfRounds) {
        self.keyMaterial = PBKDFDeriveKey(passphrase, salt: salt, rounds: rounds, size: 16)
        self.keyType = CryptoKeyType.aes(keyLength: .aes128)
        self.keyCheckValue = makeCheckValue()
    }

    public var keyByteCount: Byte {
        get { return Byte(keyMaterial.byteCount) }
    }

    func makeCheckValue() -> [Byte] {
        do {
            let zeroBuffer = ByteBuffer(size: self.keyType.blockSize)
            let cryptoText = try Cryptor.encrypt(zeroBuffer, key: self, mode: .cbc, padding: .none, initialVector: nil)
            return Array(cryptoText.values[0..<Int(kKeyCheckValueByteCount)])
        } catch {
            fatalError("Unable to generate key check value. Crypto is not working")
        }
    }

    public var keyCheckValueString: String  {
        get {
            let buffer = ByteBuffer(bytes: self.keyCheckValue)
            let hexString = buffer.hexString
            let index = hexString.characters.index(hexString.startIndex, offsetBy: Int(kKeyCheckValueByteCount * 2)) // First 6 characters is the KCV
            return hexString.substring(to: index)
        }
    }
}
