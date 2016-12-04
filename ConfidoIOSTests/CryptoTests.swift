//
//  CryptoTests.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 27/09/2015.
//

import Foundation
import XCTest
import ConfidoIOS

class CryptoTests: XCTestCase {

    func testGenerateRandomBytes() {
        let buffer1 = generateRandomBytes(20)
        XCTAssertEqual(buffer1.byteCount, 20)
        let buffer2 = generateRandomBytes(20)
        XCTAssertNotEqual(buffer1.hexString, buffer2.hexString)
    }
    func testGenerateAESKey() {
        let key = CryptoKey(keyType: .aes(keyLength: .aes128))
        print(key.keyCheckValueString)
        let zeroBuffer = ByteBuffer(size: key.keyType.blockSize)

        var cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: nil)
        let cryptoHexNilVector = cryptoText.hexString
        var decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none, initialVector: nil)

        XCTAssertEqual(decryptedText.hexString, "00000000000000000000000000000000")

        let nilInitialVector = ByteBuffer(size: key.keyType.blockSize)

        cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: nilInitialVector)
        decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none, initialVector: nilInitialVector)
        XCTAssertEqual(decryptedText.hexString, "00000000000000000000000000000000")
        XCTAssertEqual(cryptoText.hexString, cryptoHexNilVector)

        let randomInitialVector = generateRandomBytes(key.keyType.blockSize)
        cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: randomInitialVector)
        decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none, initialVector: randomInitialVector)
        XCTAssertEqual(decryptedText.hexString, "00000000000000000000000000000000")
        XCTAssertNotEqual(cryptoText.hexString, cryptoHexNilVector)
    }
    func testGenerateDESKey() {
        let key = CryptoKey(keyType: .des(keyLength: .des1))
        print(key.keyCheckValueString)
        let zeroBuffer = ByteBuffer(size: key.keyType.blockSize)

        var cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: nil)
        let cryptoHexNilVector = cryptoText.hexString
        var decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none,initialVector: nil)

        XCTAssertEqual(decryptedText.hexString, "0000000000000000")

        let nilInitialVector = ByteBuffer(size: key.keyType.blockSize)

        cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: nilInitialVector)
        decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none, initialVector: nilInitialVector)
        XCTAssertEqual(decryptedText.hexString, "0000000000000000")
        XCTAssertEqual(cryptoText.hexString, cryptoHexNilVector)

        let randomInitialVector = generateRandomBytes(key.keyType.blockSize)
        cryptoText    = try! Cryptor.encrypt(zeroBuffer, key: key, mode: .cbc, padding: .none, initialVector: randomInitialVector)
        decryptedText = try! Cryptor.decrypt(cryptoText, key: key, mode: .cbc, padding: .none, initialVector: randomInitialVector)
        XCTAssertEqual(decryptedText.hexString, "0000000000000000")
        XCTAssertNotEqual(cryptoText.hexString, cryptoHexNilVector)
    }

    func testAESTestVectorsZeroKey() {
        /*
        [ENCRYPT]

        COUNT = 0
        KEY = 00000000000000000000000000000000
        IV = 00000000000000000000000000000000
        PLAINTEXT = f34481ec3cc627bacd5dc3fb08f273e6
        CIPHERTEXT = 0336763e966d92595a567cc9ce537f5e

        COUNT = 1
        KEY = 00000000000000000000000000000000
        IV = 00000000000000000000000000000000
        PLAINTEXT = 9798c4640bad75c7c3227db910174e72
        CIPHERTEXT = a9a1631bf4996954ebc093957b234589
        */
        let key = try! CryptoKey(keyType: .aes(keyLength: .aes128), hexKeyData: "00000000000000000000000000000000")
        XCTAssertEqual(key.keyCheckValueString, "66e94b")
        XCTAssertEqual(doCrypt("00000000000000000000000000000000",testVector: "f34481ec3cc627bacd5dc3fb08f273e6",key: key), "0336763e966d92595a567cc9ce537f5e")
        XCTAssertEqual(doCrypt("00000000000000000000000000000000",testVector: "9798c4640bad75c7c3227db910174e72",key: key), "a9a1631bf4996954ebc093957b234589")
    }

    func testAESTestVectorsVarKey() {
        /*
        COUNT = 66
        KEY = ffffffffffffffffe000000000000000
        IV = 00000000000000000000000000000000
        PLAINTEXT = 00000000000000000000000000000000
        CIPHERTEXT = d9bff7ff454b0ec5a4a2a69566e2cb84

        COUNT = 67
        KEY = fffffffffffffffff000000000000000
        IV = 00000000000000000000000000000000
        PLAINTEXT = 00000000000000000000000000000000
        CIPHERTEXT = 3535d565ace3f31eb249ba2cc6765d7a

        COUNT = 68
        KEY = fffffffffffffffff800000000000000
        IV = 00000000000000000000000000000000
        PLAINTEXT = 00000000000000000000000000000000
        CIPHERTEXT = f60e91fc3269eecf3231c6e9945697c6
        */
        let key = try! CryptoKey(keyType: CryptoKeyType.aes(keyLength: AESKeyLength.aes128), hexKeyData: "ffffffffffffffffe000000000000000")
        XCTAssertEqual(key.keyCheckValueString, "d9bff7")

        XCTAssertEqual(doCrypt("00000000000000000000000000000000",
            testVector: "00000000000000000000000000000000",key: key),
            "d9bff7ff454b0ec5a4a2a69566e2cb84")
    }

    /*
    Initialization vector	Test vector Cipher text
    000102030405060708090A0B0C0D0E0F	6bc1bee22e409f96e93d7e117393172a	7649abac8119b246cee98e9b12e9197d
    7649ABAC8119B246CEE98E9B12E9197D	ae2d8a571e03ac9c9eb76fac45af8e51	5086cb9b507219ee95db113a917678b2
    5086CB9B507219EE95DB113A917678B2	30c81c46a35ce411e5fbc1191a0a52ef	73bed6b8e3c1743b7116e69e22229516
    73BED6B8E3C1743B7116E69E22229516	f69f2445df4f9b17ad2b417be66c3710	3ff1caa1681fac09120eca307586e1a7
    */
    func testAESTestVectors() {
        let key = try! CryptoKey(keyType: .aes(keyLength: .aes128), hexKeyData: "2b7e151628aed2a6abf7158809cf4f3c")
        XCTAssertEqual(doCrypt("000102030405060708090A0B0C0D0E0F",
            testVector: "6bc1bee22e409f96e93d7e117393172a",key: key),
            "7649abac8119b246cee98e9b12e9197d")
        XCTAssertEqual(doCrypt("7649ABAC8119B246CEE98E9B12E9197D",
            testVector: "ae2d8a571e03ac9c9eb76fac45af8e51",key: key),
            "5086cb9b507219ee95db113a917678b2")
    }
    func doCrypt(_ initialVector: String, testVector: String,key: CryptoKey) -> String {
        let initialVectorBuffer = try! ByteBuffer(hexData: initialVector)
        let dataBuffer          = try! ByteBuffer(hexData: testVector)
        let cryptoText = try! Cryptor.encrypt(dataBuffer, key: key, mode: .cbc, padding: .none, initialVector: initialVectorBuffer)
        return cryptoText.hexString
    }

    func testStorageWrapper() {
        let key = try! CryptoKey(keyType: .aes(keyLength: .aes128), hexKeyData: "00000000000000000000000000000000")
        XCTAssertEqual(key.keyCheckValueString, "66e94b")
        let wrappedKey = KeyStorageWrapper.wrap(key)
        XCTAssertEqual("0110000000000000000000000000000000000366e94b", wrappedKey.hexString)

        let buffer = ByteBuffer(wrappedKey)
        let unwrappedKey = try! KeyStorageWrapper.unwrap(buffer)
        XCTAssertEqual(unwrappedKey.keyCheckValueString, "66e94b")
    }
    /*
    Josefsson                     Informational                     [Page 2]

    RFC 6070               PKCS #5 PBKDF2 Test Vectors          January 2011

    2.  PBKDF2 HMAC-SHA1 Test Vectors

    */
    func testPBKDFVectors() {
        //https://www.ietf.org/rfc/rfc6070.txt
        self.measure {
            XCTAssertEqual(PBKDFDeriveKey("password", salt: "salt", rounds:        1, size: 20).hexString, "0c60c80f961f0e71f3a9b524af6012062fe037a6" )
            XCTAssertEqual(PBKDFDeriveKey("password", salt: "salt", rounds:        2, size: 20).hexString, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957" )
            XCTAssertEqual(PBKDFDeriveKey("password", salt: "salt", rounds:     4096, size: 20).hexString, "4b007901b765489abead49d926f721d065a429c1" )
            //The next one takes a long time, because it uses 16M rounds
            XCTAssertEqual(PBKDFDeriveKey("password", salt: "salt", rounds: 16777216, size: 20).hexString, "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984" )
            XCTAssertEqual(PBKDFDeriveKey("passwordPASSWORDpassword", salt: "saltSALTsaltSALTsaltSALTsaltSALTsalt", rounds: 4096, size: 25).hexString, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038" )
        }
    }

    func testDerivedAESKey() {
        let key = CryptoKey(deriveKeyFromPassphrase: "ABC", salt: "ASDASDASD")
        XCTAssertEqual(key.keyCheckValueString, "90ff0b")
    }

    func testDerivedAESKeyPerformance() {
        self.measure {
            let key = CryptoKey(deriveKeyFromPassphrase: "ABC", salt: "ASDASDASD")
            XCTAssertEqual(key.keyCheckValueString, "90ff0b")
        }
    }




}


