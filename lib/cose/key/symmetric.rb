# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class Symmetric < Base
      LABEL_K = -1

      KTY_SYMMETRIC = 4

      attr_reader :k

      def self.enforce_type(map)
        if map[LABEL_KTY] != KTY_SYMMETRIC
          raise "Not a Symmetric key"
        end
      end

      def initialize(k:, **keyword_arguments) # rubocop:disable Naming/MethodParameterName
        super(**keyword_arguments)

        if !k
          raise ArgumentError, "Required key value k is missing"
        else
          @k = k
        end
      end

      def map
        super.merge(LABEL_KTY => KTY_SYMMETRIC, LABEL_K => k)
      end

      def self.keyword_arguments_for_initialize(map)
        { k: map[LABEL_K] }
      end
    end
  end
end
