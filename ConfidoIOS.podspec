Pod::Spec.new do |spec|
  spec.name         = "ConfidoIOS"
  spec.version      = "0.1.0"
  spec.summary      = "A Library encapsulating IOS keychain access and certificates"
  spec.description  = <<-DESC
                   The library provides Object Oriented wrappers for the IOS Keychain Objects and hide the complexities of dealing with the Keychain API in IOS.
                   Includes objects for Keychain Key Pair, Keychain Certificate, etc
		   It includes support Symmetric encryption using CommonCrypto and PBKDF2 Key Derivation
                   DESC
  spec.homepage     = "https://github.com/curoo/ConfidoIOS"
  spec.license      = "MIT"
  spec.author       = { "Rudolph van Graan" => "rvg@curoo.com" }
  spec.platform     = :ios
  spec.ios.deployment_target = "9.0"
  spec.source       = { :git => "https://github.com/curoo/ConfidoIOS.git", :tag => "v0.1.0" }
  spec.source_files = "ConfidoIOS/*.swift"
  spec.module_map   = "CommonCrypto/module.modulemap"
end
