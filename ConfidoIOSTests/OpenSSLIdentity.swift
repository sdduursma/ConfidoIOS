//
//  OpenSSLIdentity.swift
// ConfidoIOS
//
//  Created by Rudolph van Graan on 10/09/2015.
//

import Foundation


@objc open class OpenSSLIdentity : OpenSSLObject {
    @objc open fileprivate(set) var p12identityData: Data
    @objc open fileprivate(set) var friendlyName: String

    public init(p12EncodedIdentityData data: Data, friendlyName name: String) {
        self.p12identityData = data
        self.friendlyName = name
        super.init()
    }

}
