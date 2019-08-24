# frozen_string_literal: true

require "cose/recipient"
require "cose/mac0"

module COSE
  class Mac < Mac0
    CONTEXT = "MAC"

    attr_reader :recipients

    def self.keyword_arguments_for_initialize(decoded)
      super.merge(recipients: decoded.last.map { |r| COSE::Recipient.from_array(r) })
    end

    def self.tag
      97
    end

    def initialize(recipients:, **keyword_arguments)
      super(**keyword_arguments)

      @recipients = recipients
    end

    def verify(key, external_aad = nil)
      recipient = recipients.detect { |r| r.headers.kid == key.kid }

      if recipient
        super
      else
        raise(COSE::Error, "No recipient match the key")
      end
    end

    private

    def context
      CONTEXT
    end
  end
end
