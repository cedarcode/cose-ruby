# frozen_string_literal: true

require "libcbor/all"

module COSE
  module Key
    class Base
      KTY_LABEL = 1

      def self.from_cbor(cbor)
        from_map(CBOR.decode(cbor))
      end

      def self.enforce_type(map, kty, error_message)
        if map[KTY_LABEL] != kty
          raise error_message
        end
      end
    end
  end
end
