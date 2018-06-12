# frozen_string_literal: true

require "cbor"

module COSE
  module Key
    class Base
      def self.from_cbor(cbor)
        from_map(CBOR.decode(cbor))
      end
    end
  end
end
