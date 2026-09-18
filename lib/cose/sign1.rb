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

    def initialize(payload:, signature: nil, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signature = signature
    end

    def sign(key, external_aad = nil, detached_payload: nil)
      @signature = algorithm.sign(key, verification_data(external_aad, detached_payload))

      self
    end

    def verify(key, external_aad = nil, detached_payload: nil)
      if key.kid == headers.kid
        algorithm.verify(key, signature, verification_data(external_aad, detached_payload))
      else
        raise(COSE::Error, "Non matching kid")
      end
    end

    def to_array
      raise(COSE::Error, "Can't serialize a Sign1 message without a signature") unless signature

      [serialized_map(protected_headers), unprotected_headers || {}, payload, signature]
    end

    def serialize
      CBOR.encode(CBOR::Tagged.new(self.class.tag, to_array))
    end

    private

    def verification_data(external_aad = nil, detached_payload = nil)
      aad = external_aad || ZERO_LENGTH_BIN_STRING

      CBOR.encode([CONTEXT, serialized_map(protected_headers), aad, payload || detached_payload])
    end
  end
end
