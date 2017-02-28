# ConfidoIOS [![Build Status](https://www.bitrise.io/app/5c8b0db6621045f2.svg?token=WmG2LE5k38P-S70KP8crjQ&branch=master)](https://www.bitrise.io/app/5c8b0db6621045f2)

# TODO
- [ ] Add skeletons for other Keychain classes that might be needed in future (Passwords)
- [ ] Get rid of Keychain.swift
- [ ] Complete KeychainCertificate
- [ ] Complete KeychainIdentity
- [x] Add README that describes the design and usage
- [x] Add License
- [x] Rename Repository to final name before publishing
- [ ] Test on an actual phone
- [ ] Remove old commented code that currently serve as documentation
- [ ] Add a local testing services that can issue Certificates
- [ ] Write a test case that generates a CSR, request a certificate from the service and import it

This is a major rewrite because the previous attempts didn't work. I used Swift 2, protocol extensions and exceptions (throws) throughout which made the implementation much saner.

# General Design
The purpose of this Library is to add the infrastructure for Client Side authentication into IOS Apps. This means that you need to deal with the IOS Keychain. Apple's APIs are severely limited and do not provide support for generating certificate signing requests (CSRs) at all. To do this, the library uses OpenSSL.

The library provides Object Oriented wrappers for the IOS Keychain Objects and hide the complexities of dealing with the Keychain API in IOS.

The classes have been designed so that it should be relatively straightforward to extend the Library to also provide OO wrappers for OpenSSL objects that implement the same protocols as the Keychain Objects in this library.

For security purposes, we decided not to use OpenSSL's functions for generating Key Pairs, because it uses a software Pseudo Random Generator, whereas Apple's APIs uses hardware security. For this reason `KeychainKeyPair` provides mechanism to export raw keys from the Keychain so that they can be used in OpenSSL. This is potentially something that should be improved, because the actual cryptographic data is in the clear in memory in these objects. The correct way to do it is to generate a storage key when the Library is instantiated (using `SecKeyGenerate`) and then immediately encrypt the output of `SecItemCopyMatching(...)` under this key and then store the Key Data encrypted in Memory. The encrypted keys should be passed to the OpenSSL wrapper and only be decrypted right before they are needed. This will prevent anyone from inspecting the memory and extracting the sensitive data. (The Storage Key will be in the IOS Keychain, which is a secure container on the iPhone and iPad).

# KeychainItem
The basic design is this. The Apple keychain uses Dictionaries for the input and output of the four SecXYZ functions. It can store 5 types of items (Keys, two kinds of Passwords, Identities and Certificates).

Apple's `secItemCopyMatching(...)` [API](https://developer.apple.com/library/ios/documentation/Security/Reference/keychainservices/index.html#//apple_ref/c/func/SecItemCopyMatching) returns the details of things in the IOS keychain. These things are instances of `KeychainItem`:
* `KeychainKey`
* `KeychainKeyPair`
* `KeychainCertificate`
* `KeychainIdentity`
These classes represent actual items in the IOS Keychain.

`KeychainItem` has a Security Class and a dictionary of Keychain Attributes.

# KeychainDescriptor
`KeychainDescriptor` is the base class for the data needed for IOS Keychain queries. This class also has a Security Class and a Dictionary of Keychain Attributes.

# Transport Classes
* `TransportKeyPair`
* `TransportPublicKey`
* `TransportPrivateKey`
* `TransportCertificate`
* `TransportIdentity`

# Importing an Identity
In order to add something (like a PKCS12 Identity from a .p12 file), you first have to import it. This you do with a call to `SecPKCS12Import(...)`. This returns a temporary reference to an Identity, but it is not stored in the keychain yet. In order to add it, the code uses objects named `TransportXYZ` to store these temporary values. In the case of an identity, this class is called `TransportKeyPair`. `TransportKeyPair` supports the `KeychainAddable` protocol, which means it has a method `addToKeychain() -> KeychainIdentity`. The Transport classes derive from `KeychainDescriptor`.

# OpenSSL
This Library uses a precompiled OpenSSL library to speed up compile time used in some unit tests.

# Keychain Protocols
## KeyChainAttributeStorage
```
public protocol KeyChainAttributeStorage {
var attributes : [String : AnyObject] { get }
subscript(attribute: String) -> AnyObject? { get }
}
```
## KeychainMatchable
Indicates that items in the IOS keychain of securityClass can matched with `keychainMatchPropertyValues()`

Returns the properties to pass to SecItemCopyMatching() to match IOS keychain items wit
```
public protocol KeychainMatchable {
func keychainMatchPropertyValues() -> [ String: AnyObject ]
var securityClass: SecurityClass { get }
}
```
## KeychainFindable
Marks that the item provides a findInKeychain() method that returns matching keychain items
```
public protocol KeychainFindable {
associatedtype QueryType : KeychainMatchable
associatedtype ResultType : KeychainItem
static func findInKeychain(matchingProperties: QueryType) throws -> ResultType?
}
```
## KeychainAddable
Indicates that the item can be added to the IOS keychain
```
public protocol KeychainAddable {
associatedtype KeychainClassType : KeychainItem, KeychainFindable
func addToKeychain() throws -> KeychainClassType?
}
```
## SecItemAddable
Generic Protocol to mark that the item can be added to the IOS Keychain
```
public protocol SecItemAddable {
func secItemAdd() throws -> AnyObject?
}
```

# HELP
## FAQ
Q: I'm getting an `header /usr/include/CommonCrypto/CommonCrypto.h not found` error.

A: Try reinstalling Xcode tools using `xcode-select --install`
