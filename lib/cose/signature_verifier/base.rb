# frozen_string_literal: true

require "cose/error"

module COSE
  module SignatureVerifier
    class Base
      def initialize(algorithm)
        @algorithm = algorithm
      end

      def verify(key, signature, verification_data)
        valid_signature?(key, signature, verification_data) || raise(COSE::Error, "Verification failed")
      end

      private

      attr_reader :algorithm

      def hash_function
        algorithm.hash_function
      end
    end
  end
end
