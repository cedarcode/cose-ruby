# frozen_string_literal: true

require "cbor"
require "cose/security_message"

module COSE
  class Sign1 < SecurityMessage
    attr_reader :payload, :signature

    def self.keyword_arguments_for_initialize(decoded)
      { payload: CBOR.decode(decoded[0]), signature: decoded[1] }
    end

    def initialize(payload:, signature:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signature = signature
    end
  end
end
