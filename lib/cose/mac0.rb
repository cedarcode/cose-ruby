# frozen_string_literal: true

require "cbor"
require "cose/security_message"
require "openssl"

module COSE
  class Mac0 < SecurityMessage
    BYTE_LENGTH = 8
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
      tag == mac(key, external_aad) || raise(COSE::Error, "Mac0 verification failed")
    end

    private

    def mac(key, external_aad = nil)
      mac = OpenSSL::HMAC.digest(algorithm.hash_function, key.k, data(external_aad))

      if algorithm.tag_length
        mac.byteslice(0, algorithm.tag_length / BYTE_LENGTH)
      else
        mac
      end
    end

    def data(external_aad = nil)
      CBOR.encode([CONTEXT, serialized_map(protected_headers), external_aad || zero_length_bin_string, payload])
    end
  end
end
