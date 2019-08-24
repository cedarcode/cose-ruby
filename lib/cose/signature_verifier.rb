# frozen_string_literal: true

require "cose/error"
require "cose/signature_verifier/ecdsa"
require "cose/signature_verifier/pss"

module COSE
  module SignatureVerifier
    def self.for(algorithm)
      case algorithm.name
      when /\AES/
        COSE::SignatureVerifier::ECDSA.new(algorithm)
      when /\APS/
        COSE::SignatureVerifier::PSS.new(algorithm)
      else
        raise(COSE::Error, "Unsupported verification for algorithm '#{algorithm.name}'")
      end
    end
  end
end
