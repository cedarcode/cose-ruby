# frozen_string_literal: true

require "cose/algorithm/signature_algorithm"
require "cose/error"
require "openssl"

RSpec.describe COSE::Algorithm::SignatureAlgorithm do
  # A minimal concrete subclass, just enough to exercise the base class's #sign rescue
  # behavior in isolation, without depending on a specific algorithm's key/curve requirements.
  let(:algorithm_class) do
    Class.new(described_class) do
      private

      def valid_key?(_key)
        true
      end

      def to_pkey(key)
        key
      end
    end
  end

  let(:algorithm) { algorithm_class.new(-7, "TEST") }

  describe "#sign" do
    it "wraps an OpenSSL::OpenSSLError raised while generating the signature into a COSE::Error" do
      # e.g. OpenSSL::ASN1::ASN1Error, which ECDSA's der_to_raw can raise.
      allow(algorithm).to receive(:generate_signature).and_raise(OpenSSL::ASN1::ASN1Error, "boom")

      expect { algorithm.sign(:key, "data") }.to raise_error(COSE::Error, /Signing failed/)
    end

    it "wraps an ArgumentError raised while generating the signature into a COSE::Error" do
      allow(algorithm).to receive(:generate_signature).and_raise(ArgumentError, "bad arg")

      expect { algorithm.sign(:key, "data") }.to raise_error(COSE::Error, /Signing failed/)
    end

    it "doesn't rescue a COSE::Error raised while generating the signature" do
      allow(algorithm).to receive(:generate_signature).and_raise(COSE::Error, "Incompatible key for algorithm")

      expect { algorithm.sign(:key, "data") }.to raise_error(COSE::Error, "Incompatible key for algorithm")
    end
  end
end
