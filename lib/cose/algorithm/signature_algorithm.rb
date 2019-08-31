# frozen_string_literal: true

require "cose/algorithm/base"
require "cose/error"

module COSE
  module Algorithm
    class SignatureAlgorithm < Base
      def verify(key, signature, verification_data)
        valid_signature?(key, signature, verification_data) || raise(COSE::Error, "Signature verification failed")
      end
    end
  end
end
