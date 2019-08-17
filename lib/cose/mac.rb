# frozen_string_literal: true

require "cbor"
require "cose/recipient"
require "cose/security_message"

module COSE
  class Mac < SecurityMessage
    attr_reader :payload, :tag, :recipients

    def self.keyword_arguments_for_initialize(decoded)
      {
        payload: CBOR.decode(decoded[0]),
        tag: decoded[1],
        recipients: decoded[2].map { |s| COSE::Recipient.deserialize(s) }
      }
    end

    def initialize(payload:, tag:, recipients:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @tag = tag
      @recipients = recipients
    end
  end
end
