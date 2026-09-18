# frozen_string_literal: true

require "cose/algorithm/base"
require "cose/error"
require "openssl"

module COSE
  module Algorithm
    class SignatureAlgorithm < Base
      def verify(key, signature, verification_data)
        compatible_key?(key) || raise(COSE::Error, "Incompatible key for signature verification")
        valid_signature?(key, signature, verification_data) || raise(COSE::Error, "Signature verification failed")
      end

      def sign(key, data)
        compatible_key?(key) || raise(COSE::Error, "Incompatible key for signature generation")

        begin
          generate_signature(to_pkey(key), data)
        rescue ArgumentError, OpenSSL::OpenSSLError => e
          raise(COSE::Error, "Signing failed: #{e.message}")
        end
      end

      def compatible_key?(key)
        valid_key?(key) && to_pkey(key)
      rescue COSE::Error
        false
      end

      private

      def generate_signature(_pkey, _data)
        raise(COSE::Error, "Signing not supported for this algorithm")
      end

      def valid_signature?(key, signature, verification_data)
        signature_algorithm = signature_algorithm_class.new(**signature_algorithm_parameters)

        begin
          signature_algorithm.verify_key = to_pkey(key)
          signature_algorithm.verify(signature, verification_data)
        rescue OpenSSL::SignatureAlgorithm::Error
          false
        end
      end

      def signature_algorithm_parameters
        { hash_function: hash_function }
      end

      def to_cose_key(key)
        case key
        when COSE::Key::Base
          key
        when OpenSSL::PKey::PKey
          COSE::Key.from_pkey(key)
        else
          raise(COSE::Error, "Don't know how to transform #{key.class} to COSE::Key")
        end
      end

      def signature_algorithm_class
        raise NotImplementedError
      end

      def valid_key?(_key)
        raise NotImplementedError
      end

      def to_pkey(_key)
        raise NotImplementedError
      end
    end
  end
end
