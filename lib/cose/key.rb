# frozen_string_literal: true

require "cbor"
require "cose/key/ec2"
require "cose/key/okp"
require "cose/key/rsa"
require "cose/key/symmetric"
require "openssl"

module COSE
  class Error < StandardError; end
  class KeyDeserializationError < Error; end
  class MalformedKeyError < KeyDeserializationError; end
  class UnknownKeyType < KeyDeserializationError; end

  module Key
    def self.serialize(pkey)
      from_pkey(pkey).serialize
    end

    def self.from_pkey(pkey)
      case pkey
      when OpenSSL::PKey::EC, OpenSSL::PKey::EC::Point
        COSE::Key::EC2.from_pkey(pkey)
      when OpenSSL::PKey::RSA
        COSE::Key::RSA.from_pkey(pkey)
      when OpenSSL::PKey::PKey
        COSE::Key::OKP.from_pkey(pkey)
      else
        raise "Unsupported #{pkey.class} object"
      end
    end

    def self.deserialize(data)
      map = cbor_decode(data)

      case map[Base::LABEL_KTY]
      when COSE::Key::OKP::KTY_OKP
        COSE::Key::OKP.from_map(map)
      when COSE::Key::EC2::KTY_EC2
        COSE::Key::EC2.from_map(map)
      when COSE::Key::RSA::KTY_RSA
        COSE::Key::RSA.from_map(map)
      when COSE::Key::Symmetric::KTY_SYMMETRIC
        COSE::Key::Symmetric.from_map(map)
      when nil
        raise COSE::UnknownKeyType, "Missing required key type kty label"
      else
        raise COSE::UnknownKeyType, "Unsupported or unknown key type #{map[Base::LABEL_KTY]}"
      end
    end

    def self.cbor_decode(data)
      CBOR.decode(data)
    rescue CBOR::MalformedFormatError, EOFError, FloatDomainError, RegexpError, TypeError, URI::InvalidURIError
      raise COSE::MalformedKeyError, "Malformed CBOR key input"
    end
  end
end
