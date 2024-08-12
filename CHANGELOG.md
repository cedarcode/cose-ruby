# Changelog

## [v1.3.1] - 2024-08-12

- Handling COSE EC keys encoded without leading 0 bytes in coordinates (#64). Credits to @waltercacau.

## [v1.3.0] - 2022-10-28

- Add support for EdDSA (#55). Credits to @bdewater.

## [v1.2.1] - 2022-07-03

- Support OpenSSL ~>3.0.0. Credits to @ClearlyClaire <3

## [v1.2.0] - 2020-07-10

### Added

- Support ES256K signature algorithm

## [v1.1.0] - 2020-07-09

### Dependencies

- Update `openssl-signature_algorithm` runtime dependency from `~> 0.4.0` to `~> 1.0`.

## [v1.0.0] - 2020-03-29

### Added

- Signature verification validates key `alg` is compatible with the signature algorithm

NOTE: No breaking changes. Moving out of `v0.x` to express the intention to keep the public API stable.

## [v0.11.0] - 2020-01-30

### Added

- Let others easily support more signature algorithms by making `COSE::Algorithm::SignatureAlgorithm` smarter

## [v0.10.0] - 2019-12-19

### Added

- Works on ruby 2.7 without throwing any warnings
- Simpler way to rescue key deserialization error, now possible to:
  ```rb
    begin
      COSE::Key.deserialize(cbor)
    rescue COSE::KeyDeserializationError
      # handle error
    end
  ```

## [v0.9.0] - 2019-08-31

### Added

- `COSE::Sign1#verify`
- `COSE::Sign#verify`
- `COSE::Mac0#verify`
- `COSE::Mac#verify`

## [v0.8.0] - 2019-08-17

### Added

- Support `COSE::Key` instantiation based on an `OpenSSL::PKey` object with `COSE::Key.from_pkey`
- Provide writer methods for `COSE::Key` Common Parameters (`#base_iv=`, `#key_ops=`, `#alg=` and `#kid=`)

## [v0.7.0] - 2019-05-02

### Fixed

- `require "cose"` now correctly requires all features

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

[v1.3.0]: https://github.com/cedarcode/cose-ruby/compare/v1.2.1...v1.3.0/
[v1.2.1]: https://github.com/cedarcode/cose-ruby/compare/v1.2.0...v1.2.1/
[v1.2.0]: https://github.com/cedarcode/cose-ruby/compare/v1.1.0...v1.2.0/
[v1.1.0]: https://github.com/cedarcode/cose-ruby/compare/v1.0.0...v1.1.0/
[v1.0.0]: https://github.com/cedarcode/cose-ruby/compare/v0.11.0...v1.0.0/
[v0.11.0]: https://github.com/cedarcode/cose-ruby/compare/v0.10.0...v0.11.0/
[v0.10.0]: https://github.com/cedarcode/cose-ruby/compare/v0.9.0...v0.10.0/
[v0.9.0]: https://github.com/cedarcode/cose-ruby/compare/v0.8.0...v0.9.0/
[v0.8.0]: https://github.com/cedarcode/cose-ruby/compare/v0.7.0...v0.8.0/
[v0.7.0]: https://github.com/cedarcode/cose-ruby/compare/v0.6.1...v0.7.0/
[v0.6.1]: https://github.com/cedarcode/cose-ruby/compare/v0.6.0...v0.6.1/
[v0.6.0]: https://github.com/cedarcode/cose-ruby/compare/v0.5.0...v0.6.0/
[v0.5.0]: https://github.com/cedarcode/cose-ruby/compare/v0.4.1...v0.5.0/
[v0.4.1]: https://github.com/cedarcode/cose-ruby/compare/v0.4.0...v0.4.1/
[v0.4.0]: https://github.com/cedarcode/cose-ruby/compare/v0.3.0...v0.4.0/
[v0.3.0]: https://github.com/cedarcode/cose-ruby/compare/v0.2.0...v0.3.0/
[v0.2.0]: https://github.com/cedarcode/cose-ruby/compare/v0.1.0...v0.2.0/
[v0.1.0]: https://github.com/cedarcode/cose-ruby/compare/5725d9b5db978f19a21bd59182f092d31a118eff...v0.1.0/
