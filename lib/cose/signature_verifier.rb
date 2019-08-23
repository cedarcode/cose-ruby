# frozen_string_literal: true

require "cose/algorithm"
require "cose/error"
require "openssl"

module COSE
  class SignatureVerifier
    BYTE_LENGTH = 8

    def initialize(alg, key)
      @alg = alg
      @key = key
    end

    def verify(signature, verification_data)
      if algorithm
        pkey.verify(algorithm.hash_function, raw_to_der(signature), verification_data) ||
          raise(COSE::Error, "Verification failed")
      else
        raise(COSE::Error, "Unknown algorithm #{alg}")
      end
    end

    private

    attr_reader :alg, :key

    def pkey
      @pkey ||= key.to_pkey
    end

    def algorithm
      case alg
      when COSE::Algorithm
        alg
      else
        COSE::Algorithm.find(alg)
      end
    end

    # Borrowed from jwt rubygem.
    # https://github.com/jwt/ruby-jwt/blob/7a6a3f1dbaff806993156d1dff9c217bb2523ff8/lib/jwt/security_utils.rb#L34-L39
    #
    # Hopefully this will be provided by openssl rubygem in the future.
    def raw_to_der(signature)
      n = (key_length.to_f / BYTE_LENGTH).ceil
      r = signature[0..(n - 1)]
      s = signature[n..-1]

      OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
    end

    def key_length
      pkey.group.degree
    end
  end
end
