//
//  TrustPoint.swift
//  IOSKeychain
//
//  Created by Rudolph van Graan on 15/09/2015.
//

import Foundation
import Security


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

public struct TrustPoint {
    var secTrust : SecTrust
    let trustAnchor : TrustAnchorPoint?
    let certificate: Certificate?
    public init(secTrust: SecTrust, certificate: Certificate?, trustAnchor: TrustAnchorPoint? = nil) throws {
        self.secTrust = secTrust
        self.certificate = certificate
        self.trustAnchor = trustAnchor
    }

    public func evaluateTrust() throws -> TrustResult {
        return try evaluateTrust(1)
    }
    func evaluateTrust(depth: Int) throws -> TrustResult {
        var secTrustResultType : SecTrustResultType = 0
//        try setTrustAnchorCertificatesOnly(false)

        if trustAnchor != nil {
            try setTrustAnchorCertificates()
            try setTrustAnchorCertificatesOnly(true)
        }
        let status = KeychainStatus.statusFromOSStatus(
            SecTrustEvaluate(secTrust, &secTrustResultType)
        )
        if status == .OK {
            let trustResult = TrustResult(rawValue: Int(secTrustResultType))!
            if trustResult == .Proceed || trustResult == .Unspecified {
                return trustResult
            } else if trustResult == TrustResult.RecoverableTrustFailure {
                return TrustResult.Deny
            }
            throw KeychainError.TrustError(trustResult: trustResult, reason: getLastTrustError())
        }
        throw status
    }

    func getTopAnchorCertificate() -> Certificate? {
        if trustAnchor != nil && trustAnchor!.certificates.count > 0 {
            return trustAnchor!.certificates[0]
        }
        return nil
    }

    static func evaluateSSLCertificateTrust(certificate: Certificate, trustAnchorPoint: TrustAnchorPoint?) -> TrustResult {
        return TrustResult.Proceed
    }

    func getTrustExceptions() -> NSData  {
        return SecTrustCopyExceptions(secTrust)
    }

    func setTrustAnchorCertificates() throws {
        var status : OSStatus

        status = SecTrustSetAnchorCertificates(secTrust, getAnchorTrustRefs())
        if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
    }

    func getAnchorTrustRefs() -> [SecCertificate] {
        //TODO: Reverse results so that the root as at the end
        if trustAnchor != nil {
            return trustAnchor!.certificates.map{ $0.secCertificate }
        } else {
            return []
        }
    }

    func setTrustAnchorCertificatesOnly(only: Bool) throws {
        var status : OSStatus
        status = SecTrustSetAnchorCertificatesOnly(secTrust, only)
        if status != 0 { throw KeychainStatus.statusFromOSStatus(status)}
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

public class TrustAnchorPoint {
    let baseX509policy : SecPolicy
    var anchorCertificate: Certificate! = nil
    public private (set) var certificates : [ Certificate ] = []
    public init() {
        baseX509policy = SecPolicyCreateBasicX509()
    }
    public init(anchorCertificate: Certificate) {
        self.anchorCertificate = anchorCertificate
        baseX509policy = SecPolicyCreateBasicX509()
        certificates.append(anchorCertificate)
    }

    public func addCertificate(certificate: Certificate, evaluateTrust: Bool = false) throws {
        if evaluateTrust {
            let trust = try trustPoint(certificate)
            let trustResult = try trust.evaluateTrust()
            if trustResult != TrustResult.Unspecified {
                throw trustResult
            }
        }
        certificates.append(certificate)
    }

    public func trustPoint(secTrust: SecTrust) throws -> TrustPoint {
        return try TrustPoint(secTrust: secTrust, certificate: nil, trustAnchor: self)
    }

    public func trustPoint(certificate: Certificate, additionalCertificates: [Certificate] = []) throws -> TrustPoint {
        let secTrust = try certificate.trust(additionalCertificates, policies: trustPolicies())
        return try TrustPoint(secTrust: secTrust, certificate: certificate, trustAnchor: self)
    }


    func trustPolicies() -> [SecPolicy] {
        return [ baseX509policy ]
    }
}
