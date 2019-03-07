require "cbor"
require "cose/security_message"

module COSE
  class Mac0 < SecurityMessage
    attr_reader :payload, :tag

    def self.keyword_arguments_for_initialize(decoded)
      { payload: CBOR.decode(decoded[0]), tag: decoded[1] }
    end

    def initialize(payload:, tag:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @tag = tag
    end
  end
end
