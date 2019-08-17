# frozen_string_literal: true

require "cose/security_message"

module COSE
  class Signature < SecurityMessage
    attr_reader :signature

    def self.keyword_arguments_for_initialize(decoded)
      { signature: decoded[0] }
    end

    def initialize(signature:, **keyword_arguments)
      super(**keyword_arguments)

      @signature = signature
    end
  end
end
