# frozen_string_literal: true

require "cbor"
require "cose/key"

RSpec.describe COSE::Key do
  describe ".deserialize" do
    it "returns error if unknown format" do
      expect {
        COSE::Key.deserialize(
          CBOR.encode(
            1 => 100,
            -1 => "a",
            -2 => "b"
          )
        )
      }.to raise_error(COSE::UnknownKeyFormat)
    end

    it "deserializes EC2" do
      key = COSE::Key.deserialize(
        CBOR.encode(
          1 => 2,
          -1 => 1,
          -2 => "x",
          -3 => "y",
          -4 => "d",
        )
      )

      expect(key).to be_a(COSE::Key::EC2)
    end

    it "deserializes RSA" do
      key = COSE::Key.deserialize(
        CBOR.encode(
          1 => 3,
          -1 => "n",
          -2 => "e"
        )
      )

      expect(key).to be_a(COSE::Key::RSA)
    end

    it "deserializes Symmetric" do
      key = COSE::Key.deserialize(
        CBOR.encode(
          1 => 4,
          -1 => "k"
        )
      )

      expect(key).to be_a(COSE::Key::Symmetric)
    end
  end
end
