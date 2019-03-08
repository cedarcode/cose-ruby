# frozen_string_literal: true

require "cbor"
require "cose/sign"
require "cose/signature"

RSpec.describe "COSE::Sign" do
  context ".deserialize" do
    before do
      cbor = CBOR.encode(
        [
          CBOR.encode(1 => 2),
          { 3 => 4 },
          CBOR.encode("This is the content"),
          [
            CBOR.encode([CBOR.encode(5 => 6), { 7 => 8 }, "signatureA".b]),
            CBOR.encode([CBOR.encode(9 => 10), { 11 => 12 }, "signatureB".b])
          ]
        ]
      )

      @sign = COSE::Sign.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@sign.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@sign.unprotected_headers).to eq(3 => 4)
    end

    it "returns payload" do
      expect(@sign.payload).to eq("This is the content")
    end

    it "returns the signatures" do
      expect(@sign.signatures.size).to eq(2)
      expect(@sign.signatures.all? { |s| s.is_a?(COSE::Signature) }).to be_truthy
    end
  end
end
