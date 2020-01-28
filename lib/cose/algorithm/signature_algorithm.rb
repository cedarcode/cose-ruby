# frozen_string_literal: true

require "cose/algorithm/base"
require "cose/error"

module COSE
  module Algorithm
    class SignatureAlgorithm < Base
      def verify(key, signature, verification_data)
        valid_signature?(key, signature, verification_data) || raise(COSE::Error, "Signature verification failed")
      end

      def compatible_key?(key)
        to_pkey(key)
      rescue COSE::Error
        false
      end

      private

      def valid_signature?(key, signature, verification_data)
        signature_algorithm = signature_algorithm_class.new(hash_function[3..-1])
        signature_algorithm.verify_key = to_pkey(key)

        begin
          signature_algorithm.verify(signature, verification_data)
        rescue OpenSSL::SignatureAlgorithm::Error
          false
        end
      end

      def signature_algorithm_class
        raise NotImplementedError
      end

      def to_pkey(_key)
        raise NotImplementedError
      end
    end
  end
end
