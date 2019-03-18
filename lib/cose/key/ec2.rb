# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class EC2 < Base
      ALG_LABEL = 3

      CRV_LABEL = -1
      D_LABEL = -4
      X_LABEL = -2
      Y_LABEL = -3

      KTY_EC2 = 2
      CRV_P256 = 1

      def self.from_pkey(pkey)
        curve =
          if pkey.group.curve_name == "prime256v1"
            CRV_P256
          else
            raise "Unsupported EC curve"
          end

        case pkey
        when OpenSSL::PKey::EC::Point
          public_key = pkey
        when OpenSSL::PKey::EC
          public_key = pkey.public_key
          private_key = pkey.private_key
        else
          raise "Unsupported"
        end

        if public_key
          bytes = public_key.to_bn.to_s(2)

          x_coordinate = bytes[1..32]
          y_coordinate = bytes[33..64]
        end

        if private_key
          d_coordinate = private_key.to_s(2)
        end

        new(curve: curve, x_coordinate: x_coordinate, y_coordinate: y_coordinate, d_coordinate: d_coordinate)
      end

      attr_reader :algorithm, :curve, :d_coordinate, :x_coordinate, :y_coordinate

      def initialize(algorithm: nil, curve:, d_coordinate: nil, x_coordinate:, y_coordinate:)
        if !curve
          raise ArgumentError, "Required curve is missing"
        elsif !x_coordinate
          raise ArgumentError, "Required x-coordinate is missing"
        elsif !y_coordinate
          raise ArgumentError, "Required y-coordinate is missing"
        else
          @algorithm = algorithm
          @curve = curve
          @d_coordinate = d_coordinate
          @x_coordinate = x_coordinate
          @y_coordinate = y_coordinate
        end
      end

      def serialize
        CBOR.encode(
          Base::LABEL_KTY => KTY_EC2,
          CRV_LABEL => CRV_P256,
          X_LABEL => x_coordinate,
          Y_LABEL => y_coordinate,
          D_LABEL => d_coordinate
        )
      end

      def self.from_map(map)
        enforce_type(map, KTY_EC2, "Not an EC2 key")

        new(
          algorithm: map[ALG_LABEL],
          curve: map[CRV_LABEL],
          d_coordinate: map[D_LABEL],
          x_coordinate: map[X_LABEL],
          y_coordinate: map[Y_LABEL]
        )
      end
    end
  end
end
