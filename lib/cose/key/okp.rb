# frozen_string_literal: true

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

      def map
        super.merge(LABEL_KTY => KTY_OKP)
      end
    end
  end
end
