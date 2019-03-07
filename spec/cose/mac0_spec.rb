# frozen_string_literal: true

require "cbor"
require "cose/mac0"

RSpec.describe "COSE::Mac0" do
  context ".deserialize" do
    before do
      cbor = CBOR.encode([CBOR.encode(1 => 15), {}, CBOR.encode("This is the content"), "tag".b])

      @mac0 = COSE::Mac0.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@mac0.protected_headers).to eq(1 => 15)
    end

    it "returns unprotected headers" do
      expect(@mac0.unprotected_headers).to eq({})
    end

    it "returns payload" do
      expect(@mac0.payload).to eq("This is the content")
    end

    it "returns the signature" do
      expect(@mac0.tag).to eq("tag".b)
    end
  end
end
