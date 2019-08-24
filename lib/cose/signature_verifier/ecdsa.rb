# frozen_string_literal: true

require "cose/signature_verifier/base"
require "openssl"

module COSE
  module SignatureVerifier
    class ECDSA < Base
      BYTE_LENGTH = 8

      private

      def valid_signature?(key, signature, verification_data)
        pkey = key.to_pkey

        pkey.verify(hash_function, raw_to_der(signature, pkey.group.degree), verification_data)
      end

      # Borrowed from jwt rubygem.
      # https://github.com/jwt/ruby-jwt/blob/7a6a3f1dbaff806993156d1dff9c217bb2523ff8/lib/jwt/security_utils.rb#L34-L39
      #
      # Hopefully this will be provided by openssl rubygem in the future.
      def raw_to_der(signature, key_length)
        n = (key_length.to_f / BYTE_LENGTH).ceil
        r = signature[0..(n - 1)]
        s = signature[n..-1]

        OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
      end
    end
  end
end
