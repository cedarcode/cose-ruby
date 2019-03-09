# frozen_string_literal: true

require "cbor"
require "cose/sign1"

RSpec.describe "COSE::Sign1" do
  context ".deserialize" do
    before do
      cbor = create_security_message({ 1 => -7 }, { 4 => "11" }, CBOR.encode("This is the content"), "signature".b)

      @sign1 = COSE::Sign1.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@sign1.protected_headers).to eq(1 => -7)
    end

    it "returns unprotected headers" do
      expect(@sign1.unprotected_headers).to eq(4 => "11")
    end

    it "returns payload" do
      expect(@sign1.payload).to eq("This is the content")
    end

    it "returns the signature" do
      expect(@sign1.signature).to eq("signature".b)
    end
  end
end
