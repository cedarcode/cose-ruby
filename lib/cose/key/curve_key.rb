# frozen_string_literal: true

require "cose/key/base"
require "openssl"

module COSE
  module Key
    class CurveKey < Base
      LABEL_CRV = -1
      LABEL_X = -2
      LABEL_D = -4

      attr_reader :crv, :d, :x

      def self.keyword_arguments_for_initialize(map)
        {
          crv: map[LABEL_CRV],
          x: map[LABEL_X],
          d: map[LABEL_D]
        }
      end

      def initialize(crv:, x: nil, d: nil, **keyword_arguments) # rubocop:disable Naming/MethodParameterName
        super(**keyword_arguments)

        if !crv
          raise ArgumentError, "Required crv is missing"
        elsif !x && !d
          raise ArgumentError, "x and d cannot be missing simultaneously"
        else
          @crv = crv
          @x = x
          @d = d
        end
      end

      def map
        super.merge(
          LABEL_CRV => crv,
          LABEL_X => x,
          LABEL_D => d
        ).compact
      end
    end
  end
end
