//
//  Identity.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation
import Security


public protocol Identity {
    associatedtype CertificateType : Certificate
    associatedtype KeyPairType  : KeyPair
    var certificate: CertificateType { get }
    var keyPair: KeyPairType { get }
}

open class IdentityReference {
    open let secItemRef : SecIdentity
    public init(reference: SecIdentity) {
        self.secItemRef = reference
    }
}

open class IdentitySpecifier : KeychainDescriptor {
    public init(itemLabel: String) {
            super.init(securityClass: .identity, itemLabel: itemLabel)
    }

    class func encodeKeyAppLabel(_ keyAppLabel: String?) -> Data? {
        if keyAppLabel == nil { return nil }
        return keyAppLabel!.data(using: String.Encoding.utf8, allowLossyConversion: true)
    }
}


//TODO: Identify protocol
open class KeychainIdentity: KeychainItem, KeychainFindable, GenerateKeychainFind {
    public typealias QueryType = IdentityDescriptor
    public typealias ResultType = KeychainIdentity
    open let keyPair : KeychainKeyPair?
    open let certificate : KeychainCertificate?
    open let secIdentity: SecIdentity

    class func getSecIdentity(SecItemAttributes attributes: NSDictionary) -> SecIdentity {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecIdentityGetTypeID() {
                let secIdentity = (valueRef as! SecIdentity)
                return secIdentity
            }
        }
        fatalError("No CertificateRef found")
    }


    open class func identityFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainIdentity {
        let keyPair = try KeychainKeyPair(SecItemAttributes: attributes)
        let certificate = try KeychainCertificate(SecItemAttributes: attributes)
        let secIdentity = getSecIdentity(SecItemAttributes: attributes as NSDictionary)
        return KeychainIdentity(secIdentity: secIdentity, keyPair: keyPair, certificate: certificate)
    }


    open class func identity(_ matchingDescriptor: IdentityDescriptor) throws -> KeychainIdentity? {
        let keyItem = try Keychain.fetchItem(matchingDescriptor: matchingDescriptor)
        if keyItem is KeychainIdentity {
            return keyItem as? KeychainIdentity
        }
        return nil
    }

/**
    Imports an Identity from pkcs12 Encoded Data
    :param: pkcs12EncodedData
    :param: protectedWithPassphrase
    :param: label An optional label to be associated with the identity when added to the Keychain
    :returns: A TransportIdentity than can be added to the Keychain
*/
    open class func importIdentity(_ pkcs12EncodedData: Data, protectedWithPassphrase passPhrase: String, label: String? = nil) throws -> TransportIdentity {
        var options : KeyChainPropertiesData = [ : ]

        options[kSecImportExportPassphrase as String] = passPhrase as AnyObject?

        let items = try SecurityWrapper.secPKCS12Import(pkcs12EncodedData, options: options)
        if items.count == 1 {
            let secIdentity : SecIdentity          = items[0][kSecImportItemIdentity as String] as! SecIdentityRef
            let secTrust    : SecTrust             = items[0][kSecImportItemTrust as String] as! SecTrustRef
            let certificateChain: [SecCertificate] = items[0][kSecImportItemCertChain as String] as! [SecCertificateRef]
            return TransportIdentity(secIdentity: secIdentity,secTrust: secTrust, certificates: certificateChain, itemLabel: label)
        }
        fatalError("No SecIdentity Reference returned")
    }

    init(secIdentity: SecIdentity, keyPair: KeychainKeyPair, certificate: KeychainCertificate) {
        self.secIdentity = secIdentity
        self.keyPair = keyPair
        self.certificate = certificate
        super.init(securityClass: .identity)
    }

}


/**
Container class for an identity in a transportable format
*/
open class TransportIdentity : KeychainDescriptor, SecItemAddable {
    open fileprivate(set) var secTrust: SecTrust!
    open fileprivate(set) var secIdentity: SecIdentity!
    open fileprivate(set) var certificates: [SecCertificate] = []
    let label : String?
    public init(secIdentity: SecIdentity, secTrust: SecTrust, certificates: [SecCertificate], itemLabel: String? = nil) {
        self.label = itemLabel
        super.init(securityClass: SecurityClass.identity, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secIdentity
        self.secTrust = secTrust
        self.secIdentity = secIdentity
        self.certificates = certificates
    }
    open func addToKeychain() throws -> KeychainIdentity {
        let importDescriptor = IdentityImportDescriptor(identity: self, label: self.label)
        try importDescriptor.secItemAdd()
        let result = try KeychainIdentity.findInKeychain(IdentityDescriptor(identityLabel: self.label))
        return result!
    }
}



open class IdentityImportDescriptor : KeyChainAttributeStorage, SecItemAddable {
    open var attributes : [String : AnyObject] = [ : ]
    public init(identity: TransportIdentity, label: String?) {
        attributes[String(kSecValueRef)] = identity.secIdentity
        if let label = label {
            attributes[String(kSecAttrLabel)] = label as AnyObject?
        }
    }
    open func secItemAdd() throws -> AnyObject? {
        var item : KeyChainPropertiesData = [ : ]
        item += self.attributes
        let itemRef: AnyObject? = try SecurityWrapper.secItemAdd(item)
        return itemRef
    }

}


open class IdentityDescriptor : KeychainDescriptor {
    public init(identityDescriptor: IdentityDescriptor) {
        super.init(descriptor: identityDescriptor)
    }

    public init(identityLabel: String? = nil) {
            super.init(securityClass: .identity, itemLabel: identityLabel)
    }
}

