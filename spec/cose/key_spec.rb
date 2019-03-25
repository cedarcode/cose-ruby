# frozen_string_literal: true

require "cbor"
require "cose/key"
require "openssl"

RSpec.describe COSE::Key do
  describe ".serialize" do
    it "can serialize EC P-256 key" do
      key = OpenSSL::PKey::EC.new("prime256v1").generate_key

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(1)
      expect(map[-2]).to be_truthy
      expect(map[-3]).to be_truthy
      expect(map[-4]).to be_truthy
    end

    it "can serialize EC P-384 key" do
      key = OpenSSL::PKey::EC.new("secp384r1").generate_key

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(2)
      expect(map[-2]).to be_truthy
      expect(map[-3]).to be_truthy
      expect(map[-4]).to be_truthy
    end

    it "can serialize EC P-521 key" do
      key = OpenSSL::PKey::EC.new("secp521r1").generate_key

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(3)
      expect(map[-2]).to be_truthy
      expect(map[-3]).to be_truthy
      expect(map[-4]).to be_truthy
    end

    it "can serialize RSA key" do
      key = OpenSSL::PKey::RSA.new(2048)

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(3)
      expect(map[-1]).to be_truthy
      expect(map[-2]).to be_truthy
      expect(map[-3]).to be_truthy
      expect(map[-4]).to be_truthy
      expect(map[-5]).to be_truthy
      expect(map[-6]).to be_truthy
      expect(map[-7]).to be_truthy
      expect(map[-8]).to be_truthy
    end

    it "can serialize RSA public key" do
      key = OpenSSL::PKey::RSA.new(2048).public_key

      cbor = COSE::Key.serialize(key)
      map = CBOR.decode(cbor)

      expect(map[1]).to eq(3)
      expect(map[-1]).to be_truthy
      expect(map[-2]).to be_truthy
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
