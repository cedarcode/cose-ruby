# frozen_string_literal: true

require "cose/encrypt"
require "cose/recipient"

RSpec.describe "COSE::Encrypt" do
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

      @encrypt = COSE::Encrypt.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@encrypt.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@encrypt.unprotected_headers).to eq(3 => 4)
    end

    it "returns the recipients" do
      expect(@encrypt.recipients.size).to eq(2)
      expect(@encrypt.recipients.all? { |s| s.is_a?(COSE::Recipient) }).to be_truthy
    end
  end
end
