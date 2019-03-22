# frozen_string_literal: true

require "cbor"
require "cose/key/symmetric"

RSpec.describe COSE::Key::Symmetric do
  it "returns an error if key value is missing" do
    expect {
      COSE::Key::Symmetric.new(key_value: nil)
    }.to raise_error(ArgumentError, "Required key value is missing")
  end

  it "returns an error if key type is wrong" do
    expect {
      COSE::Key::Symmetric.deserialize(
        CBOR.encode(
          1 => 2,
          -1 => "k"
        )
      )
    }.to raise_error("Not a Symmetric key")
  end

  it "can decode CBOR" do
    key = COSE::Key::Symmetric.deserialize(
      CBOR.encode(
        1 => 4,
        -1 => "k"
      )
    )

    expect(key.key_value).to eq("k")
  end
end
