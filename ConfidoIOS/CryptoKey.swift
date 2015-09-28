//
//  CryptoKey.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 27/09/2015.
//

import Foundation
import Security
import CommonCrypto


public enum CryptoError : ErrorType, CustomStringConvertible {
    case NoKeyFound
    case KVCMismatch(expected: [Byte], got: [Byte])
    case KeySizeMismatch(expected: Int, got: Int)


    public var description: String {
        switch self {
        case .NoKeyFound:
            return "NoKeyFound"
        case .KVCMismatch(let expected, let got):
            return "Key KVC mismatch expected [\(expected)] got [\(got)]"
        case .KeySizeMismatch(let expected, let got):
            return "Key length mismatch expected [\(expected)]  bytes got [\(got)] bytes"
        }
    }
}


public enum DESKeyLength {
    case DES1, DES3
}
public enum AESKeyLength {
    case AES128, AES192, AES256
}

public let kCryptorAESKeyType : Byte = 1
public let kCryptorDESKeyType : Byte = 2

public let kKeyCheckValueByteCount : Byte = 3

public enum CryptoKeyType : CustomStringConvertible {
    case AES(keyLength: AESKeyLength)
    case DES(keyLength: DESKeyLength)
    public init?(keyTypeCode: Byte, keyLength: Byte) {
        switch keyTypeCode {
        case kCryptorAESKeyType:
            switch keyLength {
            case 16: self = AES(keyLength: .AES128)
            case 24: self = AES(keyLength: .AES192)
            case 32: self = AES(keyLength: .AES256)
            default: return nil
            }
        case kCryptorDESKeyType:
            switch keyLength {
            case 7:  self = DES(keyLength: .DES1)
            case 21: self = DES(keyLength: .DES3)
            default: return nil
            }
        default: return nil
        }
    }

    public var rawValue: [Byte] {
        switch self {
        case AES(let keyLength) where keyLength == AESKeyLength.AES128: return [kCryptorAESKeyType,16]
        case AES(let keyLength) where keyLength == AESKeyLength.AES192: return [kCryptorAESKeyType,24]
        case AES(let keyLength) where keyLength == AESKeyLength.AES256: return [kCryptorAESKeyType,32]
        case DES(let keyLength) where keyLength == DESKeyLength.DES1:   return [kCryptorDESKeyType,7]
        case DES(let keyLength) where keyLength == DESKeyLength.DES3:   return [kCryptorDESKeyType,21]
        default: return []
        }
    }

    public var description: String {
        switch self {
        case AES(let keyLength): return "AES-\(keyLength)"
        case DES(let keyLength) where keyLength == DESKeyLength.DES1:   return "DES"
        case DES(let keyLength) where keyLength == DESKeyLength.DES3:   return "3DES"
        default: return "-"
        }
    }
    public var keySize: Int {
        switch self {
        case AES(let keyLength) where keyLength == AESKeyLength.AES128: return kCCKeySizeAES128
        case AES(let keyLength) where keyLength == AESKeyLength.AES192: return kCCKeySizeAES192
        case AES(let keyLength) where keyLength == AESKeyLength.AES256: return kCCKeySizeAES256
        case DES(let keyLength) where keyLength == DESKeyLength.DES1:   return kCCKeySizeDES
        case DES(let keyLength) where keyLength == DESKeyLength.DES3:   return kCCKeySize3DES
        default: assertionFailure("Logic error - this code should not be called"); return 0
        }
    }
    public var coreCryptoAlgorithm: Int {
        switch self {
        case AES( _): return kCCAlgorithmAES
        case DES(let keyLength) where keyLength == DESKeyLength.DES1: return kCCAlgorithmDES
        case DES(let keyLength) where keyLength == DESKeyLength.DES3: return kCCAlgorithm3DES
        default: assertionFailure("Logic error - this code should not be called"); return 0
        }
    }
    public var blockSize: Int {
        switch self {
        case AES( _): return kCCBlockSizeAES128
        case DES(let keyLength) where keyLength == DESKeyLength.DES1: return kCCBlockSizeDES
        case DES(let keyLength) where keyLength == DESKeyLength.DES3: return kCCBlockSize3DES
        default: assertionFailure("Logic error - this code should not be called"); return 0
        }
    }
}

public enum CipherMode : RawRepresentable {
    case ECB, CBC
    public init?(rawValue: Int) {
        switch rawValue {
        case kCCOptionECBMode:  self = ECB
        case 0:                 self = CBC
        default: return nil
        }
    }
    public var rawValue: Int {
        switch self {
        case ECB:  return kCCOptionECBMode
        case CBC:  return 0
        }
    }
}

public enum Padding : RawRepresentable {
    case None, PKCS7
    public init?(rawValue: Int) {
        switch rawValue {
        case 0: self = None
        case kCCOptionPKCS7Padding: self = PKCS7
        default: return nil
        }
    }
    public var rawValue: Int {
        switch self {
        case None:  return 0
        case PKCS7: return kCCOptionPKCS7Padding
        }
    }
}

public func generateRandomBytes(size: Int) -> Buffer<Byte> {
    do {
        let keyBuffer = Buffer<Byte>(size: size)
        try secEnsureOK(SecRandomCopyBytes(kSecRandomDefault, size, keyBuffer.pointer))
        return keyBuffer
    }
    catch {
        assertionFailure("Could not generate random bytes")
        return Buffer<Byte>()
    }
}


public class KeyStorageWrapper {
    /**
    Returns a raw, storable representation of the key material
    The buffer stores (1) The type of Key, (2) A Key Check Value (KCV) (3) the actual cryptographic key
    */
    public class func wrap(key: CryptoKey) -> Buffer<Byte> {
        var buffer = Buffer<Byte>()
        buffer.append(key.keyType.rawValue)             // Type and length of Key (Two bytes)
        buffer.append(key.keyMaterial.values)
        buffer.append([kKeyCheckValueByteCount])        // Length of KCV
        buffer.append(key.keyCheckValue)
        return buffer
    }

    public class func unwrap(buffer: Buffer<Byte>) throws -> CryptoKey {
        if buffer.byteCount < 1 + 1 + 1 + 3 {
            throw CryptoError.NoKeyFound
        }
        if let keyType = CryptoKeyType.init(keyTypeCode: buffer.values[0], keyLength: buffer.values[1]) {
            var startIndex  = buffer.values.startIndex
            startIndex = startIndex.advancedBy(2) // Skip keyTypeCode, keyLength
            var endIndex = startIndex.advancedBy(Int(buffer.values[1]))
            let keyData = buffer.values[Range<Int>(start: startIndex, end: endIndex)]
            let kvcLength = buffer.values[endIndex]
            if kvcLength != kKeyCheckValueByteCount {

            }
            startIndex = endIndex.advancedBy(1)
            endIndex = startIndex.advancedBy(Int(kvcLength))

            let kvcData = buffer.values[Range<Int>(start: startIndex, end: endIndex)]
            let key = try CryptoKey(keyType: keyType, keyData: Array(keyData))
            if key.keyCheckValue == Array(kvcData) {
                return key
            }
            throw CryptoError.KVCMismatch(expected: Array(kvcData), got: key.keyCheckValue)
        }
        throw CryptoError.NoKeyFound
    }
}



public struct CryptoKey {
    public let keyType:  CryptoKeyType
    let keyMaterial:     Buffer<Byte>
    var keyCheckValue:   [Byte] = []

    public init(keyType: CryptoKeyType) {
        self.keyType = keyType
        self.keyMaterial = generateRandomBytes(keyType.keySize)
        self.keyCheckValue = makeCheckValue()
    }

    public init(keyType: CryptoKeyType, hexKeyData: String) throws {
        self.keyType = keyType
        if hexKeyData.characters.count != keyType.keySize * 2 {
            throw KeychainError.DataExceedsBlockSize(size: keyType.keySize * 2)
        }
        try self.keyMaterial = Buffer<Byte>(hexData: hexKeyData)
        self.keyCheckValue = makeCheckValue()
    }

    public init(keyType: CryptoKeyType, keyData: [Byte]) throws {
        self.keyType = keyType
        if keyData.count != keyType.keySize {
            throw CryptoError.KeySizeMismatch(expected: keyType.keySize, got: keyData.count)
        }

        self.keyMaterial = Buffer<Byte>(bytes: keyData)
        self.keyCheckValue = makeCheckValue()
    }

    public var keyByteCount: Byte {
        get { return Byte(keyMaterial.byteCount) }
    }

    func makeCheckValue() -> [Byte] {
        do {
            let zeroBuffer = Buffer<Byte>(size: self.keyType.blockSize)
            let cryptoText = try Cryptor.encrypt(zeroBuffer, key: self, mode: .CBC, padding: .None, initialVector: nil)
            return Array(cryptoText.values[0..<Int(kKeyCheckValueByteCount)])
        } catch {
            fatalError("Unable to generate key check value. Crypto is not working")
        }
    }

    public var keyCheckValueString: String  {
        get {
            let buffer = Buffer<Byte>(bytes: self.keyCheckValue)
            let hexString = buffer.hexString
            let index = hexString.startIndex.advancedBy(Int(kKeyCheckValueByteCount * 2)) // First 6 characters is the KCV
            return hexString.substringToIndex(index)
        }
    }
}
