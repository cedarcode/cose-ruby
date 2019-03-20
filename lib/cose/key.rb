require "cbor"
require "cose/key/ec2"
require "cose/key/rsa"
require "cose/key/symmetric"
require "openssl"

module COSE
  class UnknownKeyType < StandardError; end

  module Key
    def self.serialize(pkey)
      case pkey
      when OpenSSL::PKey::EC, OpenSSL::PKey::EC::Point
        COSE::Key::EC2.from_pkey(pkey).serialize
      when OpenSSL::PKey::RSA
        COSE::Key::RSA.from_pkey(pkey).serialize
      else
        raise "Unsupported serialization of #{pkey.class} object"
      end
    end

    def self.deserialize(data)
      map = CBOR.decode(data)

      case map[Base::LABEL_KTY]
      when COSE::Key::EC2::KTY_EC2
        COSE::Key::EC2.from_map(map)
      when COSE::Key::RSA::KTY_RSA
        COSE::Key::RSA.from_map(map)
      when COSE::Key::Symmetric::KTY_SYMMETRIC
        COSE::Key::Symmetric.from_map(map)
      else
        raise UnknownKeyType, "Unsupported or unknown key type #{map[Base::LABEL_KTY]}"
      end
    end
  end
end
