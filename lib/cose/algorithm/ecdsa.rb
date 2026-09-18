# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/error"
require "cose/key/curve"
require "cose/key/ec2"
require "openssl"
require "openssl/signature_algorithm/ecdsa"

module COSE
  module Algorithm
    class ECDSA < SignatureAlgorithm
      attr_reader :hash_function, :curve

      def initialize(*args, hash_function:, curve_name:)
        super(*args)

        @hash_function = hash_function
        @curve = COSE::Key::Curve.by_name(curve_name) || raise("Couldn't find curve with name='#{curve_name}'")
      end

      private

      def generate_signature(pkey, data)
        der_to_raw(pkey.sign(hash_function, data), pkey.group.degree)
      end

      # OpenSSL::PKey::EC#sign returns an ASN1 DER encoded ECDSA-Sig-Value (a SEQUENCE of two
      # INTEGERs, r and s), while COSE (RFC 8152 8.1) requires the raw concatenation of r and s,
      # each padded to the curve's coordinate length.
      def der_to_raw(der_signature, degree)
        coordinate_length = (degree + 7) / 8

        OpenSSL::ASN1.decode(der_signature).value.map do |integer|
          pad_coordinate(integer.value.to_s(2), coordinate_length)
        end.join
      end

      def pad_coordinate(coordinate, length)
        padding_required = length - coordinate.bytesize
        return coordinate if padding_required <= 0

        ("\x00".b * padding_required) + coordinate
      end

      def valid_key?(key)
        cose_key = to_cose_key(key)

        cose_key.is_a?(COSE::Key::EC2) && (!cose_key.alg || cose_key.alg == id)
      end

      def signature_algorithm_class
        OpenSSL::SignatureAlgorithm::ECDSA
      end

      def signature_algorithm_parameters
        if curve
          super.merge(curve: curve.pkey_name)
        else
          super
        end
      end

      def to_pkey(key)
        case key
        when COSE::Key::EC2
          key.to_pkey
        when OpenSSL::PKey::EC
          key
        else
          raise(COSE::Error, "Incompatible key for algorithm")
        end
      end
    end
  end
end
