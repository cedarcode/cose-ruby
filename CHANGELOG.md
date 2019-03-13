# Changelog

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

[v0.4.0]: https://github.com/cedarcode/cose-ruby/compare/v0.3.0...v0.4.0/
[v0.3.0]: https://github.com/cedarcode/cose-ruby/compare/v0.2.0...v0.3.0/
[v0.2.0]: https://github.com/cedarcode/cose-ruby/compare/v0.1.0...v0.2.0/
[v0.1.0]: https://github.com/cedarcode/cose-ruby/compare/5725d9b5db978f19a21bd59182f092d31a118eff...v0.1.0/
