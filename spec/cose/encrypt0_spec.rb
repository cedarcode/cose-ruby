# frozen_string_literal: true

require "cbor"
require "cose/encrypt0"

RSpec.describe "COSE::Encrypt0" do
  context ".from_cbor" do
    before do
      cbor = CBOR.encode([CBOR.encode(1 => 10), { 5 => "init-vector".b }, "ciphertext".b])

      @encrypt0 = COSE::Encrypt0.from_cbor(cbor)
    end

    it "returns protected headers" do
      expect(@encrypt0.protected_headers).to eq(1 => 10)
    end

    it "returns unprotected headers" do
      expect(@encrypt0.unprotected_headers).to eq(5 => "init-vector".b)
    end

    it "returns the ciphertext" do
      expect(@encrypt0.ciphertext).to eq("ciphertext".b)
    end
  end
end