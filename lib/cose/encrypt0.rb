# frozen_string_literal: true

require "cose/security_message"

module COSE
  class Encrypt0 < SecurityMessage
    attr_reader :ciphertext

    def self.keyword_arguments_for_initialize(decoded)
      { ciphertext: decoded[0] }
    end

    def initialize(ciphertext:, **keyword_arguments)
      super(**keyword_arguments)

      @ciphertext = ciphertext
    end
  end
end
