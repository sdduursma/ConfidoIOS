//
//  TrustEvaluationPoint.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 15/09/2015.
//

import Foundation
import Security


public enum TrustResult: RawRepresentable, CustomStringConvertible, Error {
    case invalid, proceed,
        deny, unspecified, recoverableTrustFailure,
        fatalTrustFailure, otherError

    public static let allValues: [TrustResult] =
    [invalid, proceed,
        deny, unspecified, recoverableTrustFailure,
        fatalTrustFailure, otherError]

    public init?(rawValue: Int) {
        if rawValue == Int(SecTrustResultType.invalid.rawValue)                        { self = .invalid }
        else if rawValue == Int(SecTrustResultType.proceed.rawValue)              { self = .proceed }
        else if rawValue == Int(SecTrustResultType.deny.rawValue)                    { self = .deny}
        else if rawValue == Int(SecTrustResultType.unspecified.rawValue)             { self = .unspecified}
        else if rawValue == Int(SecTrustResultType.recoverableTrustFailure.rawValue) { self = .recoverableTrustFailure}
        else if rawValue == Int(SecTrustResultType.fatalTrustFailure.rawValue)       { self = .fatalTrustFailure}
        else if rawValue == Int(SecTrustResultType.otherError.rawValue)              { self = .otherError}
        else {
            return nil
        }
    }

    public var rawValue: Int {
        switch self {
        case .invalid:                  return Int(SecTrustResultType.invalid.rawValue)
        case .proceed:                  return Int(SecTrustResultType.proceed.rawValue)
        case .deny:                     return Int(SecTrustResultType.deny.rawValue)
        case .unspecified:              return Int(SecTrustResultType.unspecified.rawValue)
        case .recoverableTrustFailure:  return Int(SecTrustResultType.recoverableTrustFailure.rawValue)
        case .otherError:               return Int(SecTrustResultType.otherError.rawValue)
        default: return Int(SecTrustResultType.otherError.rawValue)
        }
    }

    public var description : String {
        switch self {
        case .invalid:                  return "Invalid"
        case .proceed:                  return "Proceed"
        case .deny:                     return "Deny"
        case .unspecified:              return "Unspecified"
        case .recoverableTrustFailure:  return "RecoverableTrustFailure"
        default:                       return "OtherError"
        }
    }
}


func trustEnsureOK(_ status: OSStatus) throws {
    if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
}


public enum TrustPolicy {
    case generic
    case sslClient(name: String?)
    case sslServer(hostname: String?)
}

extension Certificate where Self:Certificate {
    public func trustPoint(_ policy: TrustPolicy, additionalCertificates certificates: [Certificate]) throws -> TrustPoint {
        let trustPolicies: [ SecPolicy]
        switch policy {
        case .generic:                 trustPolicies = [SecPolicyCreateBasicX509()]
        case .sslClient(let name):     trustPolicies = [SecPolicyCreateSSL(false, name as CFString?)]
        case .sslServer(let hostname): trustPolicies = [SecPolicyCreateSSL(true, hostname as CFString?)]
        }

        let certificateRefs = certificates.map { $0.secCertificate } + [self.secCertificate]
        var secTrustResult : SecTrust? = nil
        try trustEnsureOK(SecTrustCreateWithCertificates(certificateRefs as CFTypeRef, trustPolicies as CFTypeRef?, &secTrustResult))
        return try CertificateTrustPoint(secTrust: secTrustResult!)
    }
}

public protocol Trustable {
    var secTrust : SecTrust { get }
}


public protocol TrustPoint {
    var secTrust : SecTrust { get }
    func ensureTrusted() throws
    func ensureTrusted(_ trustAnchor: TrustAnchor) throws
    func evaluateTrust() throws -> TrustResult
    func evaluateTrust(_ trustAnchor: TrustAnchor) throws -> TrustResult
}

public struct CertificateTrustPoint: TrustPoint {
    public fileprivate(set) var secTrust: SecTrust
    public init(secTrust: SecTrust) throws {
        self.secTrust = secTrust
    }

    /**
    Ensures that the TrustPoint is trusted, otherwise throws a TrustResult Exception
    */
    public func ensureTrusted() throws {
        let result = try self.evaluateTrust()
        if result == TrustResult.proceed || result == TrustResult.unspecified {
            return
        }
        throw result
    }

    /**
    Ensures that the TrustPoint is trusted against trustAnchor, otherwise throws a TrustResult Exception
    */
    public func ensureTrusted(_ trustAnchor: TrustAnchor) throws {
        let result = try self.evaluateTrust(trustAnchor)
        if result == TrustResult.proceed || result == TrustResult.unspecified {
            return
        }
        throw result
    }

    /**
    Evaluations the trust of the TrustPoint against the built-in anchors
    */
    public func evaluateTrust() throws -> TrustResult {
        try setTrustAnchorCertificates([])
        try setTrustAnchorCertificatesOnly(false)
        return try evaluateSecTrust()
    }

    /**
    Evaluates the trust of the TrustPoint against a TrustAnchor
    */
    public func evaluateTrust(_ trustAnchor: TrustAnchor) throws -> TrustResult {
        if let anchorCertificate = trustAnchor.anchorCertificate {
            try setTrustAnchorCertificates([anchorCertificate])
        }
        try setTrustAnchorCertificatesOnly(true)
        return try evaluateSecTrust()
    }

    func evaluateSecTrust() throws -> TrustResult {
        var secTrustResultType : SecTrustResultType = SecTrustResultType(rawValue: 0)!
        try trustEnsureOK(SecTrustEvaluate(secTrust, &secTrustResultType))
        let trustResult = TrustResult(rawValue: Int(secTrustResultType.rawValue))!
        if trustResult == .proceed || trustResult == .unspecified {
            return trustResult
        } else if trustResult == TrustResult.recoverableTrustFailure {
            return TrustResult.deny
        }
        throw KeychainError.trustError(trustResult: trustResult, reason: getLastTrustError())
    }


    func getTrustExceptions() -> Data  {
        return SecTrustCopyExceptions(secTrust) as Data
    }

    func setTrustAnchorCertificates(_ anchors: [Certificate]) throws {
        let anchorRefs: [SecCertificate] = anchors.map { $0.secCertificate }
        try trustEnsureOK(SecTrustSetAnchorCertificates(secTrust, anchorRefs as CFArray))
    }

    func setTrustAnchorCertificatesOnly(_ only: Bool) throws {
        try trustEnsureOK(SecTrustSetAnchorCertificatesOnly(secTrust, only))
    }

    func getLastTrustError() -> String? {
        let properties : NSArray! = SecTrustCopyProperties(secTrust)
        for validatedCertificate in properties {
            let propDict = validatedCertificate as! [ String : String]
            if let errorMessage = propDict["value"] {
                // There is no constant in the APIs for this, only kSecPropertyTypeTitle and kSecPropertyTypeError defined
                return errorMessage
            }
        }
        return nil
    }
}



open class TrustAnchor {
    let name : String
    open fileprivate(set) var anchorCertificate: Certificate! = nil
    let parentTrustAnchor: TrustAnchor?

    init(parentTrustAnchor: TrustAnchor?, anchorCertificate: Certificate?, name: String? = nil) {
        self.parentTrustAnchor = parentTrustAnchor
        self.anchorCertificate = anchorCertificate
        if let name = name {
            self.name = name
        } else if let subject = anchorCertificate?.subject {
            self.name = subject
        } else {
            self.name = "Unspecified"
        }
    }

    /**
    Constructs an empty trust anchor
    */
    public convenience init(name: String) {
        self.init(parentTrustAnchor: nil, anchorCertificate: nil, name: name)
    }
    /**
    Creates a new root TrustAnchor anchored on a certificate
    :param: name A name for the trust anchor
    */
    public convenience init(anchorCertificate: Certificate, name: String? = nil) {
        self.init(parentTrustAnchor: nil, anchorCertificate: anchorCertificate, name: name)
    }

    /*
    Extends the trust anchor. Throws <...> if the certificate cannot be verified under this trust anchor.
    :param: certificate The certificate with which to extend the trust anchor
    :param: name The name of the new TrustAnchor
    :returns: A new TrustAnchor anchored on the current anchor
    */
    open func extendAnchor(_ certificate: Certificate, name: String? = nil) throws -> TrustAnchor {
        let trust = try certificate.trustPoint(TrustPolicy.generic,additionalCertificates:[])
        try trust.ensureTrusted(self)
        return TrustAnchor(parentTrustAnchor: self, anchorCertificate: certificate, name: name)
    }

    // Recursively construct the certificate chain from which this certificate derives
    open var certificateChain: [Certificate] {
        get {
            var certificates : [ Certificate ] = []
            if let anchorCertificate = anchorCertificate {
                certificates = [anchorCertificate]
            }
            if let certificateChain = parentTrustAnchor?.certificateChain {
                certificates.append(contentsOf: certificateChain)
            }
            return certificates
        }
    }
}
