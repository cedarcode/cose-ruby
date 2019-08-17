# frozen_string_literal: true

require "cose/security_message"

module COSE
  class Recipient < SecurityMessage
    attr_reader :ciphertext, :recipients

    def self.keyword_arguments_for_initialize(decoded)
      keyword_arguments = { ciphertext: decoded[0] }

      if decoded[1]
        keyword_arguments[:recipients] = decoded[1].map { |s| COSE::Recipient.deserialize(s) }
      end

      keyword_arguments
    end

    def initialize(ciphertext:, recipients: nil, **keyword_arguments)
      super(**keyword_arguments)

      @ciphertext = ciphertext
      @recipients = recipients
    end
  end
end
