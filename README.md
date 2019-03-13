# cose

CBOR Object Signing and Encryption (COSE) ruby library

[![Gem](https://img.shields.io/gem/v/cose.svg?style=flat-square)](https://rubygems.org/gems/cose)
[![Travis](https://img.shields.io/travis/cedarcode/cose-ruby.svg?style=flat-square)](https://travis-ci.org/cedarcode/cose-ruby)

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

```ruby
cbor_data = "..."

key = COSE::Key.deserialize(cbor_data)

case key.class
when COSE::Key::EC2
  key.curve
  key.x_coordinate
  key.y_coordinate
  key.d_coordinate
when COSE::Key::RSA
  key.modulus_n
  key.public_exponent_e
when COSE::Key::Symmetric
  key.key_value
end
```

#### EC2

```ruby
cbor_data = "..."

key = COSE::Key::EC2.deserialize(cbor_data)

key.curve
key.x_coordinate
key.y_coordinate
key.d_coordinate
```

#### Symmetric

```ruby
cbor_data = "..."

key = COSE::Key::Symmetric.deserialize(cbor_data)

key.key_value
```

#### RSA

```ruby
cbor_data = "..."

key = COSE::Key::RSA.deserialize(cbor_data)

key.modulus_n
key.public_exponent_e
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
