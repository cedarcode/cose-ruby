# frozen_string_literal: true

require "cbor"
require "cose/signature"

RSpec.describe "COSE::Signature" do
  context ".deserialize" do
    before do
      cbor = CBOR.encode([CBOR.encode(1 => 2), { 3 => 4 }, "signature".b])

      @signature = COSE::Signature.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@signature.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@signature.unprotected_headers).to eq(3 => 4)
    end

    it "returns the signature" do
      expect(@signature.signature).to eq("signature".b)
    end
  end
end
