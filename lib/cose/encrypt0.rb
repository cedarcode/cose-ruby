require "cbor"

module COSE
  class Encrypt0
    attr_reader :protected_headers, :unprotected_headers, :ciphertext

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)
      new(protected_headers: CBOR.decode(decoded[0]), unprotected_headers: decoded[1], ciphertext: decoded[2])
    end

    def initialize(protected_headers:, unprotected_headers:, ciphertext:)
      @protected_headers = protected_headers
      @unprotected_headers = unprotected_headers
      @ciphertext = ciphertext
    end
  end
end
