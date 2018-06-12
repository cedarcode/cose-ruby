# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class Symmetric < Base
      KTY_LABEL = 1

      K_LABEL = -1
      KTY_SYMMETRIC = 4

      attr_reader :key_value

      def initialize(key_value: nil)
        if !key_value
          raise ArgumentError, "Required key value is missing"
        end

        @key_value = key_value
      end

      def self.from_map(map)
        if map[KTY_LABEL] == KTY_SYMMETRIC
          new(key_value: map[K_LABEL])
        else
          raise "Not a Symmetric key"
        end
      end
    end
  end
end
