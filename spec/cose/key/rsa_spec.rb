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
        5 => "init-vector".b,
        4 => 1,
        3 => -37,
        2 => "id".b,
        1 => 3,
        -1 => "n",
        -2 => "e"
      )
    )

    expect(key.base_iv).to eq("init-vector".b)
    expect(key.key_ops).to eq(1)
    expect(key.alg).to eq(-37)
    expect(key.kid).to eq("id".b)
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

  context "#serialize" do
    it "works" do
      key = COSE::Key::RSA.new(
        kid: "id".b,
        alg: -37,
        key_ops: 1,
        base_iv: "init-vector".b,
        modulus_n: "n",
        public_exponent_e: "e"
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[5]).to eq("init-vector".b)
      expect(map[4]).to eq(1)
      expect(map[3]).to eq(-37)
      expect(map[2]).to eq("id".b)
      expect(map[1]).to eq(3)
      expect(map[-1]).to eq("n")
      expect(map[-2]).to eq("e")
    end
  end
end
