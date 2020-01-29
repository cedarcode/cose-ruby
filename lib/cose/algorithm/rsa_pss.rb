# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/key/rsa"
require "cose/error"
require "openssl"

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

      def valid_signature?(key, signature, verification_data)
        pkey = to_pkey(key)

        if pkey.respond_to?(:verify_pss)
          pkey.verify_pss(hash_function, signature, verification_data, salt_length: :digest, mgf1_hash: hash_function)
        else
          raise(COSE::Error, "Update to openssl gem >= v2.1 to have RSA-PSS support")
        end
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
