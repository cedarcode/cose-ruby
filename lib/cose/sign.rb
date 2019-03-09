require "cbor"
require "cose/security_message"
require "cose/signature"

module COSE
  class Sign < SecurityMessage
    attr_reader :payload, :signatures

    def self.keyword_arguments_for_initialize(decoded)
      { payload: CBOR.decode(decoded[0]), signatures: decoded[1].map { |s| COSE::Signature.deserialize(s) } }
    end

    def initialize(payload:, signatures:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signatures = signatures
    end
  end
end
