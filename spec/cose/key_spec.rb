# frozen_string_literal: true

require "cbor"
require "cose/key"
require "openssl"

RSpec.describe COSE::Key do
  describe ".serialize" do
    it "can serialize EC P-256 key" do
      key = OpenSSL::PKey::EC.generate("prime256v1")

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(1)
      public_key_bytes = key.public_key.to_bn.to_s(2)[1..-1]
      expect(map[-2]).to eq(public_key_bytes[0..31])
      expect(map[-3]).to eq(public_key_bytes[32..-1])
      expect(map[-4]).to eq(key.private_key.to_s(2))
    end

    it "can serialize EC P-384 key" do
      key = OpenSSL::PKey::EC.generate("secp384r1")

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(2)
      public_key_bytes = key.public_key.to_bn.to_s(2)[1..-1]
      expect(map[-2]).to eq(public_key_bytes[0..47])
      expect(map[-3]).to eq(public_key_bytes[48..-1])
      expect(map[-4]).to eq(key.private_key.to_s(2))
    end

    it "can serialize EC P-521 key" do
      key = OpenSSL::PKey::EC.generate("secp521r1")

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(3)
      public_key_bytes = key.public_key.to_bn.to_s(2)[1..-1]
      expect(map[-2]).to eq(public_key_bytes[0..65])
      expect(map[-3]).to eq(public_key_bytes[66..-1])
      expect(map[-4]).to eq(key.private_key.to_s(2))
    end

    it "can serialize RSA key" do
      key = OpenSSL::PKey::RSA.new(2048)

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(3)
      expect(map[-1]).to eq(key.params["n"].to_s(2))
      expect(map[-2]).to eq(key.params["e"].to_s(2))
      expect(map[-3]).to eq(key.params["d"].to_s(2))
      expect(map[-4]).to eq(key.params["p"].to_s(2))
      expect(map[-5]).to eq(key.params["q"].to_s(2))
      expect(map[-6]).to eq(key.params["dmp1"].to_s(2))
      expect(map[-7]).to eq(key.params["dmq1"].to_s(2))
      expect(map[-8]).to eq(key.params["iqmp"].to_s(2))
    end

    it "can serialize RSA public key" do
      key = OpenSSL::PKey::RSA.new(2048).public_key

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(3)
      expect(map[-1]).to eq(key.params["n"].to_s(2))
      expect(map[-2]).to eq(key.params["e"].to_s(2))
    end
  end

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
      }.to raise_error(COSE::UnknownKeyType, "Unsupported or unknown key type 100")
    end

    it "returns error if missing kty" do
      expect {
        COSE::Key.deserialize(
          CBOR.encode(
            -1 => "a",
            -2 => "b"
          )
        )
      }.to raise_error(COSE::UnknownKeyType, "Missing required key type kty label")
    end

    it "deserializes OKP" do
      key = COSE::Key.deserialize(
        CBOR.encode(
          1 => 1,
          -1 => 4,
          -2 => "x".b,
          -4 => "d".b
        )
      )

      expect(key).to be_a(COSE::Key::OKP)
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
