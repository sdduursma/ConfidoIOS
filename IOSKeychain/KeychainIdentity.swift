//
//  Identity.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 10/09/2015.
//  Copyright (c) 2015 Curoo Limited. All rights reserved.
//

import Foundation
import Security


public protocol Identity {
    typealias CertificateType : Certificate
    typealias KeyPairType  : KeyPair
    var certificate: CertificateType { get }
    var keyPair: KeyPairType { get }
}

public class IdentityReference {
    public let secItemRef : SecIdentityRef
    public init(reference: SecIdentityRef) {
        self.secItemRef = reference
    }
}

public class IdentitySpecifier : KeychainDescriptor {
    public init(itemLabel: String) {
            super.init(securityClass: .Identity, itemLabel: itemLabel)
    }

    class func encodeKeyAppLabel(keyAppLabel: String?) -> NSData? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.dataUsingEncoding(NSUTF8StringEncoding, allowLossyConversion: true)
    }
}

public class IdentityImportDescriptor : KeychainDescriptor {

    public init(identityReference: IdentityReference, itemLabel: String? = nil, keyAppTag: String? = nil, keyAppLabel: String? = nil) {
            super.init(securityClass: .Identity, itemLabel: nil)
            if keyAppLabel != nil {
                attributes[String(kSecAttrApplicationLabel)] = KeychainKeyDescriptor.encodeKeyAppLabel(keyAppLabel)
            }
            if keyAppTag != nil {
                attributes[String(kSecAttrApplicationTag)]   = keyAppTag!
            }
        attributes[String(kSecValueRef)] = identityReference.secItemRef
    }
}



public class P12Identity {
    let openSSLIdentity : OpenSSLIdentity
    public let importPassphrase : String
    public init(openSSLIdentity identity: OpenSSLIdentity, importPassphrase: String) {
        self.openSSLIdentity = identity
        self.importPassphrase = importPassphrase
    }

    public var p12EncodedIdentityData: NSData {
        get { return openSSLIdentity.p12identityData }
    }
}

//TODO: Identify protocol
public class KeychainIdentity //: KeychainItem, KeychainFindable 
{
//    public let keyPair : KeychainKeyPair
//    public let certificate : KeychainCertificate

/**
    Imports an Identity from pkcs12 Encoded Data
    :param: pkcs12EncodedData
    :param: protectedWithPassphrase
    :param: label An optional label to be associated with the identity when added to the Keychain
    :returns: A TransportIdentity than can be added to the Keychain
*/
    public class func importIdentity(pkcs12EncodedData: NSData, protectedWithPassphrase: String, label: String? = nil) throws -> TransportIdentity {
        return TransportIdentity()
    }
}

/**
Container class for an identity in a transportable format
*/
public class TransportIdentity {
    public func addToKeychain() throws -> KeychainIdentity {
        return KeychainIdentity()
    }
}