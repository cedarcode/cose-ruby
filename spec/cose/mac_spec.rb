# frozen_string_literal: true

require "cbor"
require "cose/mac"
require "cose/recipient"

RSpec.describe "COSE::Mac" do
  context ".deserialize" do
    before do
      cbor = create_security_message(
        { 1 => 2 },
        { 3 => 4 },
        CBOR.encode("This is the content"),
        "tag".b,
        [
          create_security_message({ 5 => 6 }, { 6 => 7 }, "ciphertextA".b),
          create_security_message({ 8 => 9 }, { 10 => 11 }, "ciphertextB".b)
        ]
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
      expect(@mac.payload).to eq("This is the content")
    end

    it "returns the tag" do
      expect(@mac.tag).to eq("tag")
    end

    it "returns the recipients" do
      expect(@mac.recipients.size).to eq(2)
      expect(@mac.recipients.all? { |s| s.is_a?(COSE::Recipient) }).to be_truthy
    end
  end
end
