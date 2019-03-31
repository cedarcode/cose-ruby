# frozen_string_literal: true

require "cose/key/base"
require "openssl"

module COSE
  module Key
    class EC2 < Base
      CRV_LABEL = -1
      D_LABEL = -4
      X_LABEL = -2
      Y_LABEL = -3

      KTY_EC2 = 2
      CRV_P256 = 1
      CRV_P384 = 2
      CRV_P521 = 3

      PKEY_CURVES = {
        CRV_P256 => "prime256v1",
        CRV_P384 => "secp384r1",
        CRV_P521 => "secp521r1"
      }.freeze

      def self.from_pkey(pkey)
        curve = PKEY_CURVES.key(pkey.group.curve_name) || raise("Unsupported EC curve #{pkey.group.curve_name}")

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
          bytes = public_key.to_bn.to_s(2)[1..-1]

          coordinate_length = bytes.size / 2

          x_coordinate = bytes[0..(coordinate_length - 1)]
          y_coordinate = bytes[coordinate_length..-1]
        end

        if private_key
          d_coordinate = private_key.to_s(2)
        end

        new(curve: curve, x_coordinate: x_coordinate, y_coordinate: y_coordinate, d_coordinate: d_coordinate)
      end

      attr_reader :curve, :d_coordinate, :x_coordinate, :y_coordinate

      def initialize(curve:, d_coordinate: nil, x_coordinate:, y_coordinate:, **keyword_arguments)
        super(**keyword_arguments)

        if !curve
          raise ArgumentError, "Required curve is missing"
        elsif !x_coordinate
          raise ArgumentError, "Required x-coordinate is missing"
        elsif !y_coordinate
          raise ArgumentError, "Required y-coordinate is missing"
        else
          @curve = curve
          @d_coordinate = d_coordinate
          @x_coordinate = x_coordinate
          @y_coordinate = y_coordinate
        end
      end

      def map
        super.merge(
          Base::LABEL_KTY => KTY_EC2,
          CRV_LABEL => curve,
          X_LABEL => x_coordinate,
          Y_LABEL => y_coordinate,
          D_LABEL => d_coordinate
        )
      end

      def to_pkey
        if PKEY_CURVES[curve]
          group = OpenSSL::PKey::EC::Group.new(PKEY_CURVES[curve])
          pkey = OpenSSL::PKey::EC.new(group)
          public_key_bn = OpenSSL::BN.new("\x04" + x_coordinate + y_coordinate, 2)
          public_key_point = OpenSSL::PKey::EC::Point.new(group, public_key_bn)
          pkey.public_key = public_key_point

          if d_coordinate
            pkey.private_key = OpenSSL::BN.new(d_coordinate, 2)
          end

          pkey
        else
          raise "Unsupported curve #{curve}"
        end
      end

      def self.keyword_arguments_for_initialize(map)
        enforce_type(map, KTY_EC2, "Not an EC2 key")

        {
          curve: map[CRV_LABEL],
          d_coordinate: map[D_LABEL],
          x_coordinate: map[X_LABEL],
          y_coordinate: map[Y_LABEL]
        }
      end
    end
  end
end
