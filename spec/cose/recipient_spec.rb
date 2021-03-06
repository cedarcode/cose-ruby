# frozen_string_literal: true

require "cose/recipient"

RSpec.describe "COSE::Recipient" do
  context ".deserialize" do
    before do
      cbor = create_security_message(
        { 1 => 2 },
        { 3 => 4 },
        "ciphertext".b,
        [
          create_security_message({ 5 => 6 }, { 6 => 7 }, "ciphertextA".b),
          create_security_message({ 8 => 9 }, { 10 => 11 }, "ciphertextB".b)
        ]
      )

      @recipient = COSE::Recipient.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@recipient.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@recipient.unprotected_headers).to eq(3 => 4)
    end

    it "returns the ciphertext" do
      expect(@recipient.ciphertext).to eq("ciphertext".b)
    end

    it "returns the recipients" do
      expect(@recipient.recipients.size).to eq(2)
      expect(@recipient.recipients.all? { |s| s.is_a?(COSE::Recipient) }).to be_truthy
    end
  end
end
