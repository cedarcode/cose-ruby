# frozen_string_literal: true

module COSE
  module Key
    # https://tools.ietf.org/html/rfc8152#section-13.1
    Curve = Struct.new(:id, :name, :pkey_name) do
      @curves = {}

      def self.register(id, name, pkey_name)
        @curves[id] = new(id, name, pkey_name)
      end

      def self.find(id)
        @curves[id]
      end

      def self.by_name(name)
        @curves.values.detect { |curve| curve.name == name }
      end

      def self.by_pkey_name(pkey_name)
        @curves.values.detect { |curve| curve.pkey_name == pkey_name }
      end

      def value
        id
      end
    end
  end
end

COSE::Key::Curve.register(1, "P-256", "prime256v1")
COSE::Key::Curve.register(2, "P-384", "secp384r1")
COSE::Key::Curve.register(3, "P-521", "secp521r1")
COSE::Key::Curve.register(6, "Ed25519", "ED25519")
COSE::Key::Curve.register(7, "Ed448", "ED448")
