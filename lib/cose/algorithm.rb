# frozen_string_literal: true

module COSE
  # https://tools.ietf.org/html/rfc8152#section-8.1
  Algorithm = Struct.new(:id, :name, :hash_function) do
    @registered = {}

    def self.register(id, name, hash_function)
      @registered[id] = COSE::Algorithm.new(id, name, hash_function)
    end

    def self.find(id)
      @registered[id]
    end

    def self.by_name(name)
      @registered.values.detect { |algorithm| algorithm.name == name }
    end

    def value
      id
    end
  end
end

COSE::Algorithm.register(-7, "ES256", "SHA256")
COSE::Algorithm.register(-35, "ES384", "SHA384")
COSE::Algorithm.register(-36, "ES512", "SHA512")
COSE::Algorithm.register(-37, "PS256", "SHA256")
COSE::Algorithm.register(-38, "PS384", "SHA384")
COSE::Algorithm.register(-39, "PS512", "SHA512")
