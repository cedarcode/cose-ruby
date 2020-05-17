# frozen_string_literal: true

require "cbor"

module COSE
  module Key
    class Base
      LABEL_BASE_IV = 5
      LABEL_KEY_OPS = 4
      LABEL_ALG = 3
      LABEL_KID = 2
      LABEL_KTY = 1

      def self.deserialize(cbor)
        from_map(CBOR.decode(cbor))
      end

      def self.from_map(map)
        enforce_type(map)

        new(
          base_iv: map[LABEL_BASE_IV],
          key_ops: map[LABEL_KEY_OPS],
          alg: map[LABEL_ALG],
          kid: map[LABEL_KID],
          **keyword_arguments_for_initialize(map)
        )
      end

      attr_accessor :kid, :alg, :key_ops, :base_iv

      def initialize(kid: nil, alg: nil, key_ops: nil, base_iv: nil)
        @kid = kid
        @alg = alg
        @key_ops = key_ops
        @base_iv = base_iv
      end

      def serialize
        CBOR.encode(map)
      end

      def map
        {
          LABEL_BASE_IV => base_iv,
          LABEL_KEY_OPS => key_ops,
          LABEL_ALG => alg,
          LABEL_KID => kid,
        }.compact
      end
    end
  end
end
