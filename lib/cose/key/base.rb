# frozen_string_literal: true

require "cbor"

module COSE
  module Key
    class Base
      def self.deserialize(cbor)
        from_map(CBOR.decode(cbor))
      end

      def self.enforce_type(map, kty, error_message)
        if map[LABEL_KTY] != kty
          raise error_message
        end
      end
    end
  end
end
