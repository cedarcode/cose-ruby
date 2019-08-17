# cose

Ruby implementation of RFC 8152 CBOR Object Signing and Encryption (COSE)

[![Gem](https://img.shields.io/gem/v/cose.svg?style=flat-square)](https://rubygems.org/gems/cose)
[![Travis](https://img.shields.io/travis/cedarcode/cose-ruby.svg?style=flat-square)](https://travis-ci.org/cedarcode/cose-ruby)

## Prerequisites

### OSX

```
brew tap pjk/libcbor
brew install libcbor
```

### Linux (APT)

```
apt-get install libcbor-dev
```

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'cose'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install cose

## Usage

### Key Objects

#### Deserialization (from CBOR to Ruby objects)

```ruby
cbor_data = "..."

key = COSE::Key.deserialize(cbor_data)
```

Once you have a `COSE::Key` instance you can either access key parameters directly and/or convert it to an
`OpenSSL::PKey::PKey` instance (if supported for the key type) for operating with it
(encrypting/decrypting, signing/verifying, etc).

```ruby
# Convert to an OpenSSL::PKey::PKey
if key.respond_to?(:to_pkey)
  openssl_pkey = key.to_pkey
end

# Access COSE key parameters
case key
when COSE::Key::OKP
  key.crv
  key.x
  key.d
when COSE::Key::EC2
  key.crv
  key.x
  key.y
  key.d
when COSE::Key::RSA
  key.n
  key.e
  key.d
  key.p
  key.q
  key.dp
  key.dq
  key.qinv
when COSE::Key::Symmetric
  key.k
end
```

If you already know which COSE key type is encoded in the CBOR data, then:

```ruby
okp_key_cbor = "..."

cose_okp_key = COSE::Key::OKP.deserialize(okp_key_cbor)

cose_okp_key.crv
cose_okp_key.x
cose_okp_key.d
```

```ruby
ec2_key_cbor = "..."

cose_ec2_key = COSE::Key::EC2.deserialize(ec2_key_cbor)

cose_ec2_key.crv
cose_ec2_key.x
cose_ec2_key.y
cose_ec2_key.d

# or

ec_pkey = cose_ec2_key.to_pkey # Instance of an OpenSSL::PKey::EC
```

```ruby
symmetric_key_cbor = "..."

cose_symmetric_key = COSE::Key::Symmetric.deserialize(symmetric_key_cbor)

cose_symmetric_key.k
```

```ruby
rsa_key_cbor = "..."

cose_rsa_key = COSE::Key::RSA.deserialize(rsa_key_cbor)

cose_rsa_key.n
cose_rsa_key.e
cose_rsa_key.d
cose_rsa_key.p
cose_rsa_key.q
cose_rsa_key.dp
cose_rsa_key.dq
cose_rsa_key.qinv

# or

rsa_pkey = cose_rsa_key.to_pkey # Instance of an OpenSSL::PKey::RSA
```

#### Serialization (from Ruby objects to CBOR)

```ruby
ec_pkey = OpenSSL::PKey::EC.new("prime256v1").generate_key

cose_ec2_key_cbor = COSE::Key.serialize(ec_pkey)
```

```ruby
rsa_pkey = OpenSSL::PKey::RSA.new(2048)

cose_rsa_key_cbor = COSE::Key.serialize(rsa_pkey)
```

### Signing Objects

#### COSE_Sign

```ruby
cbor_data = "..."

sign = COSE::Sign.deserialize(cbor_data)

sign.protected_headers
sign.unprotected_headers
sign.payload

sign.signatures.each do |signature|
  signature.protected_headers
  signature.unprotected_headers
  signature.signature
end
```

#### COSE_Sign1

```ruby
cbor_data = "..."

sign1 = COSE::Sign1.deserialize(cbor_data)

sign1.protected_headers
sign1.unprotected_headers
sign1.payload
sign1.signature
```

### MAC Objects

#### COSE_Mac

```ruby
cbor_data = "..."

mac = COSE::Mac.deserialize(cbor_data)

mac.protected_headers
mac.unprotected_headers
mac.payload
mac.tag

mac.recipients.each do |recipient|
  recipient.protected_headers
  recipient.unprotected_headers
  recipient.ciphertext

  if recipient.recipients
    recipient.recipients.each do |recipient|
      recipient.protected_headers
      recipient.unprotected_headers
      recipient.ciphertext
    end
  end
end
```

#### COSE_Mac0

```ruby
cbor_data = "..."

mac0 = COSE::Mac0.deserialize(cbor_data)

mac0.protected_headers
mac0.unprotected_headers
mac0.payload
mac0.tag
```

### Encryption Objects

#### COSE_Encrypt

```ruby
cbor_data = "..."

encrypt = COSE::Encrypt.deserialize(cbor_data)

encrypt.protected_headers
encrypt.unprotected_headers
encrypt.ciphertext

encrypt.recipients.each do |recipient|
  recipient.protected_headers
  recipient.unprotected_headers
  recipient.ciphertext

  if recipient.recipients
    recipient.recipients.each do |recipient|
      recipient.protected_headers
      recipient.unprotected_headers
      recipient.ciphertext
    end
  end
end
```

#### COSE_Encrypt0

```ruby
cbor_data = "..."

encrypt0 = COSE::Encrypt0.deserialize(cbor_data)

encrypt0.protected_headers
encrypt0.unprotected_headers
encrypt0.ciphertext
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cedarcode/cose-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
