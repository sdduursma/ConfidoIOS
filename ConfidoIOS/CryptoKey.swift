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


public enum DESKeyLength : UInt8 {
    case DES1 = 8
    case DES3 = 24
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
    case AES128 = 16
    case AES192 = 24
    case AES256 = 32
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
        case AES(let keyLength): return [kCryptorAESKeyType,keyLength.rawValue]
        case DES(let keyLength): return [kCryptorDESKeyType,keyLength.rawValue]
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
        case AES(let keyLength): return Int(keyLength.byteCount)
        case DES(let keyLength): return Int(keyLength.byteCount)
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
        try secEnsureOK(SecRandomCopyBytes(kSecRandomDefault, size, keyBuffer.mutablePointer))
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
        if let keyType = CryptoKeyType.init(keyTypeCode: buffer.values[0], keyLength: buffer.values[1]) {
            var startIndex  = buffer.values.startIndex
            startIndex = startIndex.advancedBy(2) // Skip keyTypeCode, keyLength
            var endIndex = startIndex.advancedBy(Int(buffer.values[1]))
            let keyData = buffer.values[startIndex..<endIndex]
            let kvcLength = buffer.values[endIndex]
            if kvcLength != kKeyCheckValueByteCount {
                //TODO: Raise Error
            }
            startIndex = endIndex.advancedBy(1)
            endIndex = startIndex.advancedBy(Int(kvcLength))

            let kvcData = buffer.values[startIndex..<endIndex]
            let key = try CryptoKey(keyType: keyType, keyData: Array(keyData))
            if key.keyCheckValue == Array(kvcData) {
                return key
            }
            throw CryptoError.KVCMismatch(expected: Array(kvcData), got: key.keyCheckValue)
        }
        throw CryptoError.NoKeyFound
    }
}

public let kNumberOfRounds : UInt32 = 20000


public func PBKDFDeriveKey(passphrase: String, salt: String, rounds: UInt32, size: Int, algorithm : UInt32 = UInt32(kCCPRFHmacAlgSHA1)) -> Buffer<Byte>! {
    do {
        let utf8data = passphrase.dataUsingEncoding(NSUTF8StringEncoding)
        let buffer = try Buffer<Byte>(data: utf8data!)
        let utf8salt = salt.dataUsingEncoding(NSUTF8StringEncoding)
        let saltBuffer = try Buffer<Byte>(data: utf8salt!)
        return PBKDFDeriveKey(buffer, salt: saltBuffer, rounds: rounds, size: size, algorithm: algorithm)
    } catch {
        return nil
    }

}
public func PBKDFDeriveKey(buffer: Buffer<Byte>, salt: Buffer<Byte>, rounds: UInt32, size: Int, algorithm : UInt32 = UInt32(kCCPRFHmacAlgSHA1)) -> Buffer<Byte>! {
    do {
        let bufferPointer = UnsafePointer<Int8>(buffer.voidPointer)
        let derivedKeyBuffer = Buffer<Byte>(size: size)
        try secEnsureOK(CCKeyDerivationPBKDF(UInt32(kCCPBKDF2), bufferPointer, buffer.byteCount,
            salt.pointer, salt.byteCount, algorithm, rounds,
            derivedKeyBuffer.mutablePointer, derivedKeyBuffer.byteCount))
        return derivedKeyBuffer
    } catch {
        return nil
    }
}

public struct CryptoKey {
    public let keyType:  CryptoKeyType
    let keyMaterial:     Buffer<Byte>
    var keyCheckValue:   [Byte] = []

    public init(keyType: CryptoKeyType) {
        self.keyType = keyType
        self.keyMaterial = Buffer<Byte>(bytes: generateRandomBytes(keyType.keySize).values)
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

    //Derives an AES128 key from a passphrase and salt using n rounds with PBKDF and HMAC-SHA1
    //See http://robnapier.net/aes-commoncrypto
    public init(deriveKeyFromPassphrase passphrase: String, salt: String, n rounds: UInt32 = kNumberOfRounds) {
        self.keyMaterial = PBKDFDeriveKey(passphrase, salt: salt, rounds: rounds, size: 16)
        self.keyType = CryptoKeyType.AES(keyLength: .AES128)
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
