# Changelog

## [v0.6.1] - 2019-04-06

### Fixed

- Fix COSE::Key::RSA#to_pkey for a public key

## [v0.6.0] - 2019-04-03

### Added

- Support Key Common Parameters (`#base_iv`, `key_ops`, `#alg` and `#kid`)
- Support OKP Key
- Support RSA private key serialization
- Works with ruby 2.3

### Changed

- Key type-specific parameters names better match RFC

## [v0.5.0] - 2019-03-25

### Added

- `COSE::Key.serialize(openssl_pkey)` serializes an `OpenSSL::PKey::PKey` object into CBOR data. Supports RSA keys plus
 EC keys from curves prime256v1, secp384r1 and secp521r1.
- `COSE::Key::EC2#to_pkey` converts to an `OpenSSL::PKey::EC` object
- `COSE::Key::RSA#to_pkey` converts to an `OpenSSL::PKey::RSA` object

## [v0.4.1] - 2019-03-12

### Fixed

- Fix `uninitialized constant COSE::Key::Base::LABEL_KTY` when requiring only particular key

## [v0.4.0] - 2019-03-12

### Added

- RSA public key deserialization
- Key type-agnostic deserialization

### Changed

- Keys `.from_cbor` methods changed to `.deserialize`

## [v0.3.0] - 2019-03-09

### Added

- Support deserialization of security messages:
  - COSE_Sign
  - COSE_Sign1
  - COSE_Mac
  - COSE_Mac0
  - COSE_Encrypt
  - COSE_Encrypt0
- Works with ruby 2.6

## [v0.2.0] - 2019-03-04

### Added

- Symmetric key object
- EC2 key suppors D coordinate
- Works with ruby 2.4

## [v0.1.0] - 2018-06-08

### Added

- EC2 key object
- Works with ruby 2.5

[v0.6.1]: https://github.com/cedarcode/cose-ruby/compare/v0.6.0...v0.6.1/
[v0.6.0]: https://github.com/cedarcode/cose-ruby/compare/v0.5.0...v0.6.0/
[v0.5.0]: https://github.com/cedarcode/cose-ruby/compare/v0.4.1...v0.5.0/
[v0.4.1]: https://github.com/cedarcode/cose-ruby/compare/v0.4.0...v0.4.1/
[v0.4.0]: https://github.com/cedarcode/cose-ruby/compare/v0.3.0...v0.4.0/
[v0.3.0]: https://github.com/cedarcode/cose-ruby/compare/v0.2.0...v0.3.0/
[v0.2.0]: https://github.com/cedarcode/cose-ruby/compare/v0.1.0...v0.2.0/
[v0.1.0]: https://github.com/cedarcode/cose-ruby/compare/5725d9b5db978f19a21bd59182f092d31a118eff...v0.1.0/
