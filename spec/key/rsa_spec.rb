# frozen_string_literal: true

require "cose/key/rsa"

RSpec.describe COSE::Key::RSA do
  it "returns an error if modulus_n is missing" do
    expect {
      COSE::Key::RSA.new(modulus_n: nil, public_exponent_e: "e")
    }.to raise_error(ArgumentError, "Required modulus_n is missing")
  end

  it "returns an error if public_exponent_e is missing" do
    expect {
      COSE::Key::RSA.new(modulus_n: "n", public_exponent_e: nil)
    }.to raise_error(ArgumentError, "Required public_exponent_e is missing")
  end

  it "returns an error if key type is wrong" do
    expect {
      COSE::Key::RSA.from_cbor(
        CBOR.encode(
          1 => 4,
          -1 => "n",
          -2 => "e"
        )
      )
    }.to raise_error("Not an RSA key")
  end

  it "can decode CBOR" do
    key = COSE::Key::RSA.from_cbor(
      CBOR.encode(
        1 => 3,
        -1 => "n",
        -2 => "e"
      )
    )

    expect(key.modulus_n).to eq("n")
    expect(key.public_exponent_e).to eq("e")
  end
end
