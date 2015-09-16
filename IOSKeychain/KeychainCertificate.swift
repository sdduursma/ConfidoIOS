//
//  Certificate.swift
//
//  Created by Rudolph van Graan on 23/08/2015.
//

import Foundation

public enum CertificateType {
    case RootCACertificate, IntermediateCACertificate, ClientAuthenticationSSLCertificate, ServerSSLCertificate, Unknown
}

public protocol Certificate {
    var secCertificate: SecCertificate! { get }
    var certificateType: CertificateType { get }
    func isSelfSignedCA() -> Bool
    func trust(additionalCertificates: [Certificate],policies: [SecPolicy]?) throws -> SecTrust
}

public protocol RootCACertificate : Certificate { }
public protocol IntermediateCACertificate: Certificate { }
public protocol ClientAuthenticationCertificate: Certificate { }

public class KeychainCertificate : KeychainItem,
    Certificate, KeychainCertificateClassProperties, KeychainFindable, GenerateKeychainFind {
    public typealias QueryType = TransportCertificate
    public typealias ResultType = KeychainCertificate
    public private(set) var secCertificate: SecCertificate! = nil
    public private(set) var subject: String?

    public class func keychainCertificateFromAttributes(SecItemAttributes attributes: SecItemAttributes) throws -> KeychainCertificate {
        return try KeychainCertificate(SecItemAttributes: attributes)
    }

    public class func certificate(derEncodedCertificateData: NSData, certificateType: CertificateType) throws -> TransportCertificate {
        let secCertificate = SecCertificateCreateWithData(nil, derEncodedCertificateData)
        if secCertificate != nil {
            return TransportCertificate(secCertificate: secCertificate!, certificateType: certificateType)
        }
        throw KeychainError.InvalidCertificateData
    }

    class func getSecCertificate(SecItemAttributes attributes: NSDictionary) throws -> SecCertificate {
        if let valueRef: AnyObject = attributes[String(kSecValueRef)] {
            if CFGetTypeID(valueRef) == SecCertificateGetTypeID() {
                return (valueRef as! SecCertificate)
            }
        }
        throw KeychainError.NoSecCertificateReference
    }

    public init(SecItemAttributes attributes: SecItemAttributes) throws {
        super.init(securityClass: SecurityClass.Certificate, SecItemAttributes: attributes)
        self.secCertificate = try KeychainCertificate.getSecCertificate(SecItemAttributes: attributes)
        self.subject = SecCertificateCopySubjectSummary(self.secCertificate) as String
    }

    public var certificateType: CertificateType {
        get {
            return KeychainCertificate.getCertificateType(self.secCertificate)
        }
    }

    public func isSelfSignedCA() -> Bool {
        //TODO: remove this and replace with call to KeychainCertificate.isCertificateSelfSignedCA(self.secCertificate)
        switch self.certificateType {
        case .RootCACertificate: return true
        default: return false
        }
    }


    class func getCertificateType(secCertificate: SecCertificate) -> CertificateType {
        //TODO: Look at the Certificate attributes and figure this out via OpenSSL
        return .Unknown
    }
    class func isCertificateSelfSignedCA(secCertificate: SecCertificate) -> Bool {
        //TODO: Call OpenSSL to check this
        return false
    }

    public func trust(additionalCertificates: [Certificate], policies: [SecPolicy]?) throws -> SecTrust {
        var finalPolicies : [ SecPolicy]
        if policies == nil {
            finalPolicies = [SecPolicyCreateBasicX509()]
        } else {
            finalPolicies = policies!
        }
        var secTrustResult : SecTrust? = nil
        var refs = [secCertificate]
        refs.appendContentsOf(additionalCertificates.map { $0.secCertificate })
        let osStatus = SecTrustCreateWithCertificates(refs, finalPolicies, &secTrustResult)
        if osStatus != 0 { throw KeychainStatus.statusFromOSStatus(osStatus)}
        return secTrustResult!
    }


}

/**
Container class for an identity in a transportable format
*/
public class TransportCertificate : KeychainDescriptor, SecItemAddable, Certificate {
    public private(set) var subject: String?
    public private(set) var secCertificate: SecCertificate!
    public private(set) var certificateType: CertificateType
    public init(secCertificate: SecCertificate, certificateType: CertificateType, itemLabel: String? = nil) {
        self.secCertificate = secCertificate
        //TODO: Get rid of this certificateType parameter and figure this out from OpenSSL
        self.certificateType = certificateType
        self.subject = SecCertificateCopySubjectSummary(secCertificate) as String
        super.init(securityClass: SecurityClass.Certificate, itemLabel: itemLabel)
        attributes[kSecValueRef as String] = secCertificate

    }

    public func addToKeychain() throws -> KeychainCertificate {
        try self.secItemAdd()
        return try KeychainCertificate.findInKeychain(self)!
    }

    public func isSelfSignedCA() -> Bool {
        //TODO: remove this and replace with call to KeychainCertificate.isCertificateSelfSignedCA(self.secCertificate)
        switch self.certificateType {
        case .RootCACertificate: return true
        default: return false
        }
    }

    public func trust(additionalCertificates: [Certificate], policies: [SecPolicy]?) throws -> SecTrust {
        var finalPolicies : [ SecPolicy]
        if policies == nil {
            finalPolicies = [SecPolicyCreateBasicX509()]
        } else {
            finalPolicies = policies!
        }
        var secTrustResult : SecTrust? = nil
        var refs = [secCertificate]
        refs.appendContentsOf(additionalCertificates.map { $0.secCertificate })
        let osStatus = SecTrustCreateWithCertificates(refs, finalPolicies, &secTrustResult)
        if osStatus != 0 { throw KeychainStatus.statusFromOSStatus(osStatus)}
        return secTrustResult!
    }


}

