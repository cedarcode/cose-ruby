# frozen_string_literal: true

require "cbor"

module COSE
  class SecurityMessage
    attr_reader :protected_headers, :unprotected_headers

    def self.deserialize(cbor)
      decoded = CBOR.decode(cbor)

      if decoded.respond_to?(:value)
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
  end
end
