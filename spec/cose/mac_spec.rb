# frozen_string_literal: true

require "base64"
require "cbor"
require "cose/error"
require "cose/key"
require "cose/mac"
require "cose/recipient"

RSpec.describe "COSE::Mac" do
  context ".deserialize" do
    before do
      cbor = create_security_message(
        { 1 => 2 },
        { 3 => 4 },
        "This is the content".b,
        "tag".b,
        [
          [CBOR.encode({ 5 => 6 }), { 6 => 7 }, "ciphertextA".b],
          [CBOR.encode({ 8 => 9 }), { 10 => 11 }, "ciphertextB".b]
        ],
        cbor_tag: 97
      )

      @mac = COSE::Mac.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@mac.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@mac.unprotected_headers).to eq(3 => 4)
    end

    it "returns the payload" do
      expect(@mac.payload).to eq("This is the content".b)
    end

    it "returns the tag" do
      expect(@mac.tag).to eq("tag")
    end

    it "returns the recipients" do
      expect(@mac.recipients.size).to eq(2)
      expect(@mac.recipients.all? { |s| s.is_a?(COSE::Recipient) }).to be_truthy
    end
  end

  context "#verify" do
    wg_examples("mac-tests/*.json") do |example|
      it "passes #{example['title']}" do
        mac_data = example["input"]["mac"]
        key_data = mac_data["recipients"][0]["key"]

        key = COSE::Key::Symmetric.new(
          kid: key_data["kid"],
          k: Base64.urlsafe_decode64(key_data["k"])
        )

        external_aad = hex_to_bytes(mac_data["external"])
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Mac.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Mac.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end

    wg_examples("hmac-examples/HMac-0*.json") do |example|
      it "passes #{example['title']}" do
        mac_data = example["input"]["mac"]
        key_data = mac_data["recipients"][0]["key"]

        key = COSE::Key::Symmetric.new(
          kid: key_data["kid"],
          k: Base64.urlsafe_decode64(key_data["k"])
        )

        external_aad = hex_to_bytes(mac_data["external"])
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Mac.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Mac.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end
  end
end
