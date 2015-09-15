//
//  TrustPoint.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 15/09/2015.
//

import Foundation
import Security

public class TrustPoint {
}

public enum TrustResult: RawRepresentable, CustomStringConvertible, ErrorType {
    case Invalid, Proceed,
        Deny, Unspecified, RecoverableTrustFailure,
        FatalTrustFailure, OtherError

    public static let allValues: [TrustResult] =
    [Invalid, Proceed,
        Deny, Unspecified, RecoverableTrustFailure,
        FatalTrustFailure, OtherError]

    public init?(rawValue: Int) {
        if rawValue == kSecTrustResultInvalid                        { self = Invalid }
        else if rawValue == kSecTrustResultProceed                 { self = Proceed }
        else if rawValue == kSecTrustResultDeny                    { self = Deny}
        else if rawValue == kSecTrustResultUnspecified             { self = Unspecified}
        else if rawValue == kSecTrustResultRecoverableTrustFailure { self = RecoverableTrustFailure}
        else if rawValue == kSecTrustResultFatalTrustFailure       { self = FatalTrustFailure}
        else if rawValue == kSecTrustResultOtherError              { self = OtherError}
        else {
            return nil
        }
    }

    public var rawValue: Int {
        switch self {
        case Invalid:                  return kSecTrustResultInvalid
        case Proceed:                  return kSecTrustResultProceed
        case Deny:                     return kSecTrustResultDeny
        case Unspecified:              return kSecTrustResultUnspecified
        case RecoverableTrustFailure:  return kSecTrustResultRecoverableTrustFailure
        case OtherError:               return kSecTrustResultOtherError
        default: return kSecTrustResultOtherError
        }
    }

    public var description : String {
        switch self {
        case Invalid:                  return "Invalid"
        case Proceed:                  return "Proceed"
        case Deny:                     return "Deny"
        case Unspecified:              return "Unspecified"
        case RecoverableTrustFailure:  return "RecoverableTrustFailure"
        default:                       return "OtherError"
        }
    }
}

public struct CertificateTrustEvaluationPoint {
    var secTrust : SecTrust
    let trustChain : CertificateTrustChain
    public init(secTrust: SecTrust, trustChain: CertificateTrustChain) throws {
        self.secTrust = secTrust
        self.trustChain = trustChain
    }

    public func evaluateTrust() throws -> TrustResult {
        return try evaluateTrust(1)
    }
    func evaluateTrust(depth: Int) throws -> TrustResult {
        var secTrustResultType : SecTrustResultType = 0

        let status = KeychainStatus.statusFromOSStatus(SecTrustEvaluate(secTrust, &secTrustResultType))
        if status == .OK {
            let trustResult = TrustResult(rawValue: Int(secTrustResultType))!
            if (trustResult == .RecoverableTrustFailure) && (depth == 1) {
                return try self.evaluateTrustWithAnchorCertificates(depth)
            }
            return trustResult
        }
        throw status
    }

    func evaluateTrustWithAnchorCertificates(depth: Int) throws -> TrustResult {
        let exceptions = getTrustExceptions()
        try setTrustAnchorCertificates()
        SecTrustSetExceptions(secTrust, exceptions)
        try setTrustAnchorCertificatesOnly(true)
        return try evaluateTrust(depth + 1)
    }

    func getTrustExceptions() -> NSData  {
        return SecTrustCopyExceptions(secTrust)
    }

    func setTrustAnchorCertificates() throws {
        var status : OSStatus
        status = SecTrustSetAnchorCertificates(secTrust, self.trustChain.certificates.reverse())
        if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
    }

    func setTrustAnchorCertificatesOnly(only: Bool) throws {
        var status : OSStatus
        status = SecTrustSetAnchorCertificatesOnly(secTrust, only)
        if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
    }


    public func getTrustProperties() {
        let properties = SecTrustCopyProperties(secTrust)
        print(properties)
        let exceptions = SecTrustCopyExceptions(secTrust)
        print(exceptions)
        let result = SecTrustCopyResult(secTrust)
        print(result)
        var anchors : NSArray?
        let osStatus = withUnsafeMutablePointer(&anchors) {
            SecTrustCopyCustomAnchorCertificates(secTrust, UnsafeMutablePointer($0))
        }
        print(anchors)

    }
}

public class CertificateTrustChain {
    let baseX509policy : SecPolicy
    public private (set) var certificates : [ SecCertificate ] = []
    public init(anchorCertificate: Certificate) {
        baseX509policy = SecPolicyCreateBasicX509()
        certificates.append(anchorCertificate.secCertificate)
    }

    public func addCertificate(certificate: Certificate, evaluateTrust: Bool = false) throws {
        if evaluateTrust {
            let trust = try getCertificateTrust(certificate)
            let trustResult = try trust.evaluateTrust()
            if trustResult != TrustResult.Unspecified {
                throw trustResult
            }
        }
        certificates.append(certificate.secCertificate)
    }

    public func trustEvaluationPoint(secTrust: SecTrust) throws -> CertificateTrustEvaluationPoint {
        return try CertificateTrustEvaluationPoint(secTrust: secTrust, trustChain: self)
    }

    func getCertificateTrust(certificate: Certificate) throws -> CertificateTrustEvaluationPoint {
        var secTrustResult : SecTrust? = nil
        let osStatus = SecTrustCreateWithCertificates([certificate.secCertificate], trustPolicies(), &secTrustResult)
        if osStatus != 0 { throw KeychainStatus.statusFromOSStatus(osStatus)}
        return try CertificateTrustEvaluationPoint(secTrust: secTrustResult!, trustChain: self)
    }


    func trustPolicies() -> [SecPolicy] {
        return [ baseX509policy ]
    }
}
