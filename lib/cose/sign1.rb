require "cbor"

module COSE
  class Sign1
    attr_reader :protected_headers, :unprotected_headers, :payload, :signature

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)

      new(
        protected_headers: CBOR.decode(decoded[0]),
        unprotected_headers: decoded[1],
        payload: CBOR.decode(decoded[2]),
        signature: decoded[3]
      )
    end

    def initialize(protected_headers:, unprotected_headers:, payload:, signature:)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
      @payload = payload
      @signature = signature
    end
  end
end
