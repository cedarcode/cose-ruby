require "cbor"
require "cose/security_message"

module COSE
  class Sign1 < SecurityMessage
    attr_reader :payload, :signature

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)

      new(
        protected_headers: CBOR.decode(decoded[0]),
        unprotected_headers: decoded[1],
        payload: CBOR.decode(decoded[2]),
        signature: decoded[3]
      )
    end

    def initialize(payload:, signature:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @signature = signature
    end
  end
end
