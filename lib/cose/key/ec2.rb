# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class EC2 < Base
      ALG_LABEL = 3

      CRV_LABEL = -1
      X_LABEL = -2
      Y_LABEL = -3

      KTY_EC2 = 2

      attr_reader :algorithm, :curve, :x_coordinate, :y_coordinate

      def initialize(algorithm: nil, curve:, x_coordinate:, y_coordinate:)
        if !curve
          raise ArgumentError, "Required curve is missing"
        elsif !x_coordinate
          raise ArgumentError, "Required x-coordinate is missing"
        elsif !y_coordinate
          raise ArgumentError, "Required y-coordinate is missing"
        else
          @algorithm = algorithm
          @curve = curve
          @x_coordinate = x_coordinate
          @y_coordinate = y_coordinate
        end
      end

      def self.from_map(map)
        enforce_type(map, KTY_EC2, "Not an EC2 key")

        new(
          algorithm: map[ALG_LABEL],
          curve: map[CRV_LABEL],
          x_coordinate: map[X_LABEL],
          y_coordinate: map[Y_LABEL]
        )
      end
    end
  end
end
