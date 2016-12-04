//
//  Certificate.swift
//
//  Created by Rudolph van Graan on 23/08/2015.
//

import Foundation


public protocol Certificate {
    var secCertificate: SecCertificate! { get }
    var subject: String { get }
    func trustPoint(_ policy: TrustPolicy, additionalCertificates: [Certificate]) throws -> TrustPoint
}

public protocol RootCACertificate : Certificate { }
public protocol IntermediateCACertificate: Certificate { }
public protocol ClientAuthenticationCertificate: Certificate { }

open class KeychainCertificate : KeychainItem,
    Certificate, KeychainCertificateClassProperties, KeychainFindable, GenerateKeychainFind {
    public typealias QueryType = CertificateDescriptor
    public typealias ResultType = KeychainCertificate
    open fileprivate(set) var secCertificate: SecCertificate! = nil
    open fileprivate(set) var subject: String = ""

    open class func keychainCertificateFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainCertificate {
        return try KeychainCertificate(SecItemAttributes: attributes)
    }

    open class func certificate(_ derEncodedCertificateData: Data, itemLabel: String? = nil) throws -> TransportCertificate {
        let secCertificate = SecCertificateCreateWithData(nil, derEncodedCertificateData as CFData)
        if let secCertificate = secCertificate {
            return TransportCertificate(secCertificate: secCertificate, itemLabel: itemLabel)
        }
        throw KeychainError.invalidCertificateData
    }

    class func getSecCertificate(SecItemAttributes attributes: NSDictionary) throws -> SecCertificate {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecCertificateGetTypeID() {
                return (valueRef as! SecCertificate)
            } else if CFGetTypeID(valueRef) == SecIdentityGetTypeID() {
                let secIdentity = (valueRef as! SecIdentity)
                return try secIdentity.certificateRef()
            }

        }
        fatalError("No CertificateRef found")
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.certificate, SecItemAttributes: attributes)
        self.secCertificate = try KeychainCertificate.getSecCertificate(SecItemAttributes: attributes as NSDictionary)
        self.subject = SecCertificateCopySubjectSummary(self.secCertificate)! as String
    }

}

open class CertificateDescriptor : KeychainDescriptor {
    public init(certificateDescriptor: CertificateDescriptor) {
        super.init(descriptor: certificateDescriptor)
    }

    public init(certificateLabel: String) {
        super.init(securityClass: .certificate, itemLabel: certificateLabel)
    }
}


/**
Container class for an identity in a transportable format
*/
open class TransportCertificate : KeychainDescriptor, SecItemAddable, Certificate {
    open fileprivate(set) var subject: String
    open fileprivate(set) var secCertificate: SecCertificate!
    let label : String?
    public init(secCertificate: SecCertificate, itemLabel: String? = nil) {
        self.secCertificate = secCertificate
        self.label = itemLabel
        self.subject = SecCertificateCopySubjectSummary(secCertificate)! as String
        super.init(securityClass: SecurityClass.certificate, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secCertificate

    }
    open func addToKeychain() throws -> KeychainCertificate? {
        try self.secItemAdd()
        if let label = label {
            return try KeychainCertificate.findInKeychain(CertificateDescriptor(certificateLabel: label))!
        }
        return nil
    }

}
