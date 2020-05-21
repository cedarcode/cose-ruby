# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/error"
require "cose/key/okp"
require "openssl"

module COSE
  module Algorithm
    class EDDSA < SignatureAlgorithm
      private

      def valid_key?(key)
        cose_key = to_cose_key(key)

        cose_key.is_a?(COSE::Key::OKP) && (!cose_key.alg || cose_key.alg == id)
      end

      def to_pkey(key)
        case key
        when COSE::Key::OKP
          key.to_pkey
        when OpenSSL::PKey::PKey
          key
        else
          raise(COSE::Error, "Incompatible key for algorithm")
        end
      end

      def valid_signature?(key, signature, verification_data)
        pkey = key.to_pkey

        begin
          pkey.verify(nil, signature, verification_data)
        rescue OpenSSL::PKey::PKeyError
          false
        end
      end
    end
  end
end
