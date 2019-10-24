# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/key/rsa"
require "cose/error"
require "openssl"
require "openssl/signature_algorithm/rsapss"

module COSE
  module Algorithm
    class RSAPSS < SignatureAlgorithm
      attr_reader :hash_function, :salt_length

      def initialize(*args, hash_function:, salt_length:)
        super(*args)

        @hash_function = hash_function
        @salt_length = salt_length
      end

      private

      def valid_key?(key)
        to_cose_key(key).is_a?(COSE::Key::RSA)
      end

      def signature_algorithm_class
        OpenSSL::SignatureAlgorithm::RSAPSS
      end

      def to_pkey(key)
        case key
        when COSE::Key::RSA
          key.to_pkey
        when OpenSSL::PKey::RSA
          key
        else
          raise(COSE::Error, "Incompatible key for algorithm")
        end
      end
    end
  end
end
