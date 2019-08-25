# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message"
require "cose/signature"

module COSE
  class Sign < SecurityMessage
    CONTEXT = "Signature"

    attr_reader :payload, :signatures

    def self.keyword_arguments_for_initialize(decoded)
      { payload: decoded[0], signatures: decoded[1].map { |s| COSE::Signature.from_array(s) } }
    end

    def self.tag
      98
    end

    def initialize(payload:, signatures:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signatures = signatures
    end

    def verify(key, external_aad = nil)
      signature = signatures.detect { |s| s.headers.kid == key.kid }

      if signature
        signature.algorithm.verify(key, signature.signature, verification_data(signature, external_aad))
      else
        raise(COSE::Error, "No signature matches key kid")
      end
    end

    private

    def verification_data(signature, external_aad = nil)
      @verification_data ||=
        CBOR.encode(
          [
            CONTEXT,
            serialized_map(protected_headers),
            serialized_map(signature.protected_headers),
            external_aad || ZERO_LENGTH_BIN_STRING,
            payload
          ]
        )
    end
  end
end
