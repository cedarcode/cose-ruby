# frozen_string_literal: true

require "cose/key/curve"
require "cose/key/curve_key"
require "openssl"

module COSE
  module Key
    class OKP < CurveKey
      KTY_OKP = 1

      def self.enforce_type(map)
        if map[LABEL_KTY] != KTY_OKP
          raise "Not an OKP key"
        end
      end

      def self.from_pkey(pkey)
        curve = Curve.by_pkey_name(pkey.oid) || raise("Unsupported edwards curve #{pkey.oid}")
        attributes = { crv: curve.id }

        begin
          asymmetric_key = pkey.private_to_der
          private_key = OpenSSL::ASN1.decode(asymmetric_key).value.last.value
          curve_private_key = OpenSSL::ASN1.decode(private_key).value
          attributes.merge!({ d: curve_private_key })
        rescue OpenSSL::PKey::PKeyError
          asymmetric_key = pkey.public_to_der
          public_key_bit_string = OpenSSL::ASN1.decode(asymmetric_key).value.last.value
          attributes.merge!({ x: public_key_bit_string })
        end

        new(**attributes)
      end

      def map
        super.merge(LABEL_KTY => KTY_OKP)
      end

      def to_pkey
        if curve
          private_key_algo = OpenSSL::ASN1::Sequence.new(
            [OpenSSL::ASN1::ObjectId.new(curve.pkey_name)]
          )
          seq = if d
                  version = OpenSSL::ASN1::Integer.new(0)
                  curve_private_key = OpenSSL::ASN1::OctetString.new(d).to_der
                  private_key = OpenSSL::ASN1::OctetString.new(curve_private_key)
                  [version, private_key_algo, private_key]
                else
                  public_key = OpenSSL::ASN1::BitString.new(x)
                  [private_key_algo, public_key]
                end

          asymmetric_key = OpenSSL::ASN1::Sequence.new(seq)
          OpenSSL::PKey.read(asymmetric_key.to_der)
        else
          raise "Unsupported curve #{crv}"
        end
      end

      def curve
        Curve.find(crv)
      end
    end
  end
end
