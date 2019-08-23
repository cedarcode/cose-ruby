# frozen_string_literal: true

require "cbor"
require "cose/error"
require "cose/security_message/headers"

module COSE
  class SecurityMessage
    ZERO_LENGTH_BIN_STRING = "".b

    attr_reader :protected_headers, :unprotected_headers

    def self.deserialize(cbor)
      decoded = CBOR.decode(cbor)

      if decoded.is_a?(CBOR::Tagged)
        if respond_to?(:tag) && tag != decoded.tag
          raise(COSE::Error, "Invalid CBOR tag")
        end

        decoded = decoded.value
      end

      new(
        protected_headers: CBOR.decode(decoded[0]),
        unprotected_headers: decoded[1],
        **keyword_arguments_for_initialize(decoded[2..-1])
      )
    end

    def initialize(protected_headers:, unprotected_headers:)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
    end

    def headers
      @headers ||= Headers.new(protected_headers, unprotected_headers)
    end

    private

    def serialized_map(map)
      if map && !map.empty?
        map.to_cbor
      else
        zero_length_bin_string
      end
    end

    def zero_length_bin_string
      ZERO_LENGTH_BIN_STRING
    end
  end
end
