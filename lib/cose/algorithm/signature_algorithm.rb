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

      def valid_signature?(_key, _signature, _verification_data)
        raise NotImplementedError
      end

      def to_pkey(_key)
        raise NotImplementedError
      end
    end
  end
end
