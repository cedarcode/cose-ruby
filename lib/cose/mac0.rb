# frozen_string_literal: true

require "cbor"
require "cose/security_message"
require "openssl"

module COSE
  class Mac0 < SecurityMessage
    CONTEXT = "MAC0"

    attr_reader :payload, :tag

    def self.keyword_arguments_for_initialize(decoded)
      { payload: decoded[0], tag: decoded[1] }
    end

    def self.tag
      17
    end

    def initialize(payload:, tag:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @tag = tag
    end

    def verify(key, external_aad = nil)
      tag == algorithm.mac(key.k, data(external_aad)) || raise(COSE::Error, "Mac0 verification failed")
    end

    private

    def data(external_aad = nil)
      CBOR.encode([context, serialized_map(protected_headers), external_aad || zero_length_bin_string, payload])
    end

    def context
      CONTEXT
    end
  end
end
