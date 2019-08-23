# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message"
require "cose/signature_verifier"

module COSE
  class Sign1 < SecurityMessage
    CONTEXT = "Signature1"
    HEADER_LABEL_ALG = 1
    HEADER_LABEL_KID = 4
    ZERO_LENGTH_BIN_STRING = "".b

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
      if key.kid == kid
        COSE::SignatureVerifier.new(alg, key).verify(signature, verification_data(external_aad))
      else
        raise(COSE::Error, "Non matching kid")
      end
    end

    private

    def verification_data(external_aad = nil)
      CBOR.encode([CONTEXT, serialized_map(protected_headers), external_aad || ZERO_LENGTH_BIN_STRING, payload])
    end

    def kid
      header(HEADER_LABEL_KID)
    end

    def alg
      header(HEADER_LABEL_ALG)
    end

    def header(label)
      protected_headers[label] || unprotected_headers[label]
    end

    def serialized_map(map)
      if map && !map.empty?
        map.to_cbor
      else
        ZERO_LENGTH_BIN_STRING
      end
    end
  end
end
