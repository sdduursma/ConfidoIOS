//
//  OpenSSLCertificate.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//
//

import Foundation


@objc open class OpenSSLCertificate : OpenSSLObject {
    @objc open fileprivate(set) var certificateData: Data
    public init(certificateData: Data) {
        self.certificateData = certificateData
        super.init()
    }
}

@objc open class OpenSSLCertificateSigningRequest : OpenSSLObject {
}



