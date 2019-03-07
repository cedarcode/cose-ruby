require "cose/security_message"

module COSE
  class Mac0 < SecurityMessage
    attr_reader :payload, :tag

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)

      new(
        protected_headers: CBOR.decode(decoded[0]),
        unprotected_headers: decoded[1],
        payload: CBOR.decode(decoded[2]),
        tag: decoded[3]
      )
    end

    def initialize(payload:, tag:, **keyword_arguments)
      super(**keyword_arguments)

      @payload = payload
      @tag = tag
    end
  end
end
