# frozen_string_literal: true

require "cose/signature_verifier/base"

module COSE
  module SignatureVerifier
    class PSS < Base
      private

      def valid_signature?(key, signature, verification_data)
        pkey = key.to_pkey

        if pkey.respond_to?(:verify_pss)
          pkey.verify_pss(hash_function, signature, verification_data, salt_length: :digest, mgf1_hash: hash_function)
        else
          raise(COSE::Error, "Update to openssl gem >= v2.1 to have PSS support")
        end
      end
    end
  end
end
