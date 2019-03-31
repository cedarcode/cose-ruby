# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class Symmetric < Base
      K_LABEL = -1
      KTY_SYMMETRIC = 4

      attr_reader :key_value

      def initialize(key_value:, **keyword_arguments)
        super(**keyword_arguments)

        if !key_value
          raise ArgumentError, "Required key value is missing"
        end

        @key_value = key_value
      end

      def map
        super.merge(LABEL_KTY => KTY_SYMMETRIC, K_LABEL => key_value)
      end

      def self.keyword_arguments_for_initialize(map)
        enforce_type(map, KTY_SYMMETRIC, "Not a Symmetric key")

        { key_value: map[K_LABEL] }
      end
    end
  end
end
