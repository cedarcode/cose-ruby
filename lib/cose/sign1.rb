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

    def initialize(**keyword_arguments)
      @signature = keyword_arguments.delete(:signature)
      @payload = keyword_arguments.delete(:payload)

      super(**keyword_arguments)
    end
  end
end
