# frozen_string_literal: true

require "cose/key/rsa"
require "openssl"

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
      COSE::Key::RSA.deserialize(
        CBOR.encode(
          1 => 4,
          -1 => "n",
          -2 => "e"
        )
      )
    }.to raise_error("Not an RSA key")
  end

  it "can decode CBOR" do
    key = COSE::Key::RSA.deserialize(
      CBOR.encode(
        1 => 3,
        -1 => "n",
        -2 => "e"
      )
    )

    expect(key.modulus_n).to eq("n")
    expect(key.public_exponent_e).to eq("e")
  end

  context "#to_pkey" do
    let(:original_pkey) { OpenSSL::PKey::RSA.new(2048) }

    let(:pkey) do
      COSE::Key::RSA.from_pkey(original_pkey).to_pkey
    end

    it "it generates an instance of OpenSSL::PKey::PKey" do
      expect(pkey).to be_a(OpenSSL::PKey::RSA)
    end

    it "it generates the same key" do
      pkey.params.each do |param_name, param_value|
        expect(param_value).to eq(original_pkey.params[param_name]), "expected key param #{param_name} to match"
      end
    end
  end
end
