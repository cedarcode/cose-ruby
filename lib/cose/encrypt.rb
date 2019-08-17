# frozen_string_literal: true

require "cose/security_message"
require "cose/recipient"

module COSE
  class Encrypt < SecurityMessage
    attr_reader :ciphertext, :recipients

    def self.keyword_arguments_for_initialize(decoded)
      { ciphertext: decoded[0], recipients: decoded[1].map { |s| COSE::Recipient.deserialize(s) } }
    end

    def initialize(ciphertext:, recipients:, **keyword_arguments)
      super(**keyword_arguments)

      @ciphertext = ciphertext
      @recipients = recipients
    end
  end
end
