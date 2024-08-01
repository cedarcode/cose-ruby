# frozen_string_literal: true

require "cose/key/curve"
require "cose/key/curve_key"
require "openssl"

module COSE
  module Key
    class EC2 < CurveKey
      LABEL_Y = -3

      KTY_EC2 = 2

      ZERO_BYTE = "\0".b

      def self.enforce_type(map)
        if map[LABEL_KTY] != KTY_EC2
          raise "Not an EC2 key"
        end
      end

      def self.from_pkey(pkey)
        curve = Curve.by_pkey_name(pkey.group.curve_name) || raise("Unsupported EC curve #{pkey.group.curve_name}")

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

          x = bytes[0..(coordinate_length - 1)]
          y = bytes[coordinate_length..-1]
        end

        if private_key
          d = private_key.to_s(2)
        end

        new(crv: curve.id, x: x, y: y, d: d)
      end

      attr_reader :y

      def initialize(y: nil, **keyword_arguments) # rubocop:disable Naming/MethodParameterName
        if (!y || !keyword_arguments[:x]) && !keyword_arguments[:d]
          raise ArgumentError, "Both x and y are required if d is missing"
        else
          super(**keyword_arguments)

          @y = y
        end
      end

      def map
        super.merge(
          Base::LABEL_KTY => KTY_EC2,
          LABEL_Y => y,
        ).compact
      end

      def to_pkey
        if curve
          group = OpenSSL::PKey::EC::Group.new(curve.pkey_name)
          public_key_bn = OpenSSL::BN.new("\x04" + pad_coordinate(group, x) + pad_coordinate(group, y), 2)
          public_key_point = OpenSSL::PKey::EC::Point.new(group, public_key_bn)

          # RFC5480 SubjectPublicKeyInfo
          asn1 = OpenSSL::ASN1::Sequence(
            [
              OpenSSL::ASN1::Sequence(
                [
                  OpenSSL::ASN1::ObjectId("id-ecPublicKey"),
                  OpenSSL::ASN1::ObjectId(curve.pkey_name),
                ]
              ),
              OpenSSL::ASN1::BitString(public_key_point.to_octet_string(:uncompressed))
            ]
          )

          if d
            # RFC5915 ECPrivateKey
            asn1 = OpenSSL::ASN1::Sequence(
              [
                OpenSSL::ASN1::Integer.new(1),
                # Not properly padded but OpenSSL doesn't mind
                OpenSSL::ASN1::OctetString(OpenSSL::BN.new(d, 2).to_s(2)),
                OpenSSL::ASN1::ObjectId(curve.pkey_name, 0, :EXPLICIT),
                OpenSSL::ASN1::BitString(public_key_point.to_octet_string(:uncompressed), 1, :EXPLICIT),
              ]
            )

            der = asn1.to_der
            return OpenSSL::PKey::EC.new(der)
          end

          OpenSSL::PKey::EC.new(asn1.to_der)
        else
          raise "Unsupported curve #{crv}"
        end
      end

      def curve
        Curve.find(crv)
      end

      def self.keyword_arguments_for_initialize(map)
        super.merge(y: map[LABEL_Y])
      end

      def pad_coordinate(group, coordinate)
        coordinate_length = (group.degree + 7) / 8
        padding_required = coordinate_length - coordinate.length
        return coordinate if padding_required <= 0

        (ZERO_BYTE * padding_required) + coordinate
      end
    end
  end
end
