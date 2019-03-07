require "cbor"
require "cose/security_message"

module COSE
  class Encrypt0 < SecurityMessage
    attr_reader :ciphertext

    def self.from_cbor(cbor)
      decoded = CBOR.decode(cbor)
      new(protected_headers: CBOR.decode(decoded[0]), unprotected_headers: decoded[1], ciphertext: decoded[2])
    end

    def initialize(**keyword_arguments)
      @ciphertext = keyword_arguments.delete(:ciphertext)

      super(**keyword_arguments)
    end
  end
end
