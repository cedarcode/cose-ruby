# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/error"
require "cose/key/ec2"
require "openssl"
require "openssl/signature_algorithm/ecdsa"

module COSE
  module Algorithm
    class ECDSA < SignatureAlgorithm
      attr_reader :hash_function

      def initialize(*args, hash_function:)
        super(*args)

        @hash_function = hash_function
      end

      private

      def signature_algorithm_class
        OpenSSL::SignatureAlgorithm::ECDSA
      end

      def to_pkey(key)
        case key
        when COSE::Key::EC2
          key.to_pkey
        when OpenSSL::PKey::EC
          key
        else
          raise(COSE::Error, "Incompatible key for algorithm")
        end
      end
    end
  end
end
