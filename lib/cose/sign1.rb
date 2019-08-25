# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message"

module COSE
  class Sign1 < SecurityMessage
    CONTEXT = "Signature1"

    attr_reader :payload, :signature

    def self.keyword_arguments_for_initialize(decoded)
      { payload: decoded[0], signature: decoded[1] }
    end

    def self.tag
      18
    end

    def initialize(payload:, signature:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signature = signature
    end

    def verify(key, external_aad = nil)
      if key.kid == headers.kid
        algorithm.verify(key, signature, verification_data(external_aad))
      else
        raise(COSE::Error, "Non matching kid")
      end
    end

    private

    def verification_data(external_aad = nil)
      CBOR.encode([CONTEXT, serialized_map(protected_headers), external_aad || ZERO_LENGTH_BIN_STRING, payload])
    end
  end
end
