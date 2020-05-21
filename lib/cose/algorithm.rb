# frozen_string_literal: true

require "cose/algorithm/ecdsa"
require "cose/algorithm/eddsa"
require "cose/algorithm/hmac"
require "cose/algorithm/rsa_pss"

module COSE
  module Algorithm
    @registered_by_id = {}
    @registered_by_name = {}

    def self.register(algorithm)
      @registered_by_id[algorithm.id] = algorithm
      @registered_by_name[algorithm.name] = algorithm
    end

    def self.find(id_or_name)
      by_id(id_or_name) || by_name(id_or_name)
    end

    def self.by_id(id)
      @registered_by_id[id]
    end

    def self.by_name(name)
      @registered_by_name[name]
    end

    register(ECDSA.new(-7, "ES256", hash_function: "SHA256"))
    register(ECDSA.new(-35, "ES384", hash_function: "SHA384"))
    register(ECDSA.new(-36, "ES512", hash_function: "SHA512"))
    register(EDDSA.new(-8, "EdDSA"))
    register(RSAPSS.new(-37, "PS256", hash_function: "SHA256", salt_length: 32))
    register(RSAPSS.new(-38, "PS384", hash_function: "SHA384", salt_length: 48))
    register(RSAPSS.new(-39, "PS512", hash_function: "SHA512", salt_length: 64))
    register(HMAC.new(4, "HMAC 256/64", hash_function: "SHA256", tag_length: 64))
    register(HMAC.new(5, "HMAC 256/256", hash_function: "SHA256", tag_length: 256))
    register(HMAC.new(6, "HMAC 384/384", hash_function: "SHA384", tag_length: 384))
    register(HMAC.new(7, "HMAC 512/512", hash_function: "SHA512", tag_length: 512))
  end
end
