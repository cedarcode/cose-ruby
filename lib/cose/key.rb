require "cbor"
require "cose/key/ec2"
require "cose/key/rsa"
require "cose/key/symmetric"

module COSE
  class UnknownKeyFormat < StandardError; end

  module Key
    LABEL_KTY = 1

    def self.deserialize(data)
      map = CBOR.decode(data)

      case map[LABEL_KTY]
      when COSE::Key::EC2::KTY_EC2
        COSE::Key::EC2.from_map(map)
      when COSE::Key::RSA::KTY_RSA
        COSE::Key::RSA.from_map(map)
      when COSE::Key::Symmetric::KTY_SYMMETRIC
        COSE::Key::Symmetric.from_map(map)
      else
        raise UnknownKeyFormat
      end
    end
  end
end
