module COSE
  class Mac0
    attr_reader :protected_headers, :unprotected_headers, :payload, :tag

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)

      new(
        protected_headers: CBOR.decode(decoded[0]),
        unprotected_headers: decoded[1],
        payload: CBOR.decode(decoded[2]),
        tag: decoded[3]
      )
    end

    def initialize(protected_headers:, unprotected_headers:, payload:, tag:)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
      @payload = payload
      @tag = tag
    end
  end
end
