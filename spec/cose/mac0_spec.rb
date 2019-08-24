# frozen_string_literal: true

require "base64"
require "cbor"
require "cose/key"
require "cose/mac0"

RSpec.describe "COSE::Mac0" do
  context ".deserialize" do
    before do
      cbor = create_security_message({ 1 => 15 }, {}, "This is the content".b, "tag".b, cbor_tag: 17)

      @mac0 = COSE::Mac0.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@mac0.protected_headers).to eq(1 => 15)
    end

    it "returns unprotected headers" do
      expect(@mac0.unprotected_headers).to eq({})
    end

    it "returns payload" do
      expect(@mac0.payload).to eq("This is the content".b)
    end

    it "returns the signature" do
      expect(@mac0.tag).to eq("tag".b)
    end
  end

  context "#verify" do
    wg_examples("mac0-tests/*.json") do |example|
      it "passes #{example['title']}" do
        mac0_data = example["input"]["mac0"]
        key_data = mac0_data["recipients"][0]["key"]

        external_aad = hex_to_bytes(mac0_data["external"])
        key = COSE::Key::Symmetric.new(k: Base64.urlsafe_decode64(key_data["k"]))
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Mac0.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Mac0.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end

    wg_examples("hmac-examples/HMac-enc-*.json") do |example|
      it "passes #{example['title']}" do
        mac0_data = example["input"]["mac0"]
        key_data = mac0_data["recipients"][0]["key"]

        external_aad = hex_to_bytes(mac0_data["external"])
        key = COSE::Key::Symmetric.new(k: Base64.urlsafe_decode64(key_data["k"]))
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Mac0.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Mac0.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end
  end
end
