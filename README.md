# cose

COSE ([RFC 8152](https://tools.ietf.org/html/rfc8152)) in ruby

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

#### EC2

```ruby
cbor_data = "..."

key = COSE::Key::EC2.from_cbor(cbor_data)

key.curve
key.x_coordinate
key.y_coordinate
```

#### Symmetric

```ruby
cbor_data = "..."

key = COSE::Key::Symmetric.from_cbor(cbor_data)

key.key_value
```

### Signing Objects

_Pending_

### MAC Objects

_Pending_

### Encryption Objects

_Pending_

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/cedarcode/cose-ruby.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
