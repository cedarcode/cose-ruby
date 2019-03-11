# frozen_string_literal: true

require "cose/key/base"

module COSE
  module Key
    class RSA < Base
      LABEL_N = -1
      LABEL_E = -2

      KTY_RSA = 3

      attr_reader :modulus_n, :public_exponent_e

      def initialize(modulus_n:, public_exponent_e:)
        if !modulus_n
          raise ArgumentError, "Required modulus_n is missing"
        elsif !public_exponent_e
          raise ArgumentError, "Required public_exponent_e is missing"
        else
          @modulus_n = modulus_n
          @public_exponent_e = public_exponent_e
        end
      end

      def self.from_map(map)
        enforce_type(map, KTY_RSA, "Not an RSA key")

        new(modulus_n: map[LABEL_N], public_exponent_e: map[LABEL_E])
      end
    end
  end
end
