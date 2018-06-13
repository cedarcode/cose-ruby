# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class Symmetric < Base
      K_LABEL = -1
      KTY_SYMMETRIC = 4

      attr_reader :key_value

      def initialize(key_value:)
        if !key_value
          raise ArgumentError, "Required key value is missing"
        end

        @key_value = key_value
      end

      def self.from_map(map)
        enforce_type(map, KTY_SYMMETRIC, "Not a Symmetric key")

        new(key_value: map[K_LABEL])
      end
    end
  end
end
