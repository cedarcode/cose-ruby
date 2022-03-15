# frozen_string_literal: true

require "cose/key/ec2"
require "openssl"

RSpec.describe COSE::Key::EC2 do
  describe ".new" do
    it "validates crv presence" do
      expect { COSE::Key::EC2.new(crv: nil, x: "x".b, y: "y".b) }.to raise_error("Required crv is missing")
    end

    it "validates presence of at least x and y if d missing" do
      expect {
        COSE::Key::EC2.new(crv: 4, x: nil, y: nil)
      }.to raise_error("Both x and y are required if d is missing")

      expect {
        COSE::Key::EC2.new(crv: 4, x: "x".b, y: nil)
      }.to raise_error("Both x and y are required if d is missing")

      expect {
        COSE::Key::EC2.new(crv: 4, x: nil, y: "y".b)
      }.to raise_error("Both x and y are required if d is missing")
    end

    it "can build a public key" do
      key = COSE::Key::EC2.new(crv: 4, x: "x".b, y: "y".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq("x".b)
      expect(key.y).to eq("y".b)
      expect(key.d).to eq(nil)
    end

    it "can build a private key without x and y" do
      key = COSE::Key::EC2.new(crv: 4, d: "d".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq(nil)
      expect(key.y).to eq(nil)
      expect(key.d).to eq("d".b)
    end

    it "can build a private key with x and y" do
      key = COSE::Key::EC2.new(crv: 4, x: "x".b, y: "y".b, d: "d".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq("x".b)
      expect(key.y).to eq("y".b)
      expect(key.d).to eq("d".b)
    end
  end

  describe ".deserialize" do
    it "works" do
      key = COSE::Key::EC2.deserialize(
        CBOR.encode(
          5 => "init-vector".b,
          4 => 1,
          3 => -7,
          2 => "id".b,
          1 => 2,
          -1 => 1,
          -2 => "x".b,
          -3 => "y".b,
          -4 => "d".b
        )
      )

      expect(key.base_iv).to eq("init-vector".b)
      expect(key.key_ops).to eq(1)
      expect(key.alg).to eq(-7)
      expect(key.kid).to eq("id".b)
      expect(key.crv).to eq(1)
      expect(key.x).to eq("x".b)
      expect(key.y).to eq("y".b)
      expect(key.d).to eq("d".b)
    end

    it "returns an error if key type is wrong" do
      expect {
        COSE::Key::EC2.deserialize(
          CBOR.encode(
            1 => 4,
            -1 => 1,
            -2 => "x",
            -3 => "y"
          )
        )
      }.to raise_error("Not an EC2 key")
    end
  end

  context "#to_pkey" do
    it "works for an EC key in the P-256 curve" do
      original_pkey = OpenSSL::PKey::EC.generate("prime256v1")
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("prime256v1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end

    it "works for an EC key in the P-384 curve" do
      original_pkey = OpenSSL::PKey::EC.generate("secp384r1")
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("secp384r1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end

    it "works for an EC key in the P-521 curve" do
      original_pkey = OpenSSL::PKey::EC.generate("secp521r1")
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("secp521r1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end

    it "works for an EC key in the secp256k1 curve" do
      original_pkey = OpenSSL::PKey::EC.generate("secp256k1")
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("secp256k1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end
  end

  describe "#serialize" do
    it "works" do
      key = COSE::Key::EC2.new(
        kid: "id".b,
        alg: -7,
        key_ops: 1,
        base_iv: "init-vector".b,
        crv: 1,
        x: "x".b,
        y: "y".b,
        d: "d".b
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[5]).to eq("init-vector".b)
      expect(map[4]).to eq(1)
      expect(map[3]).to eq(-7)
      expect(map[2]).to eq("id".b)
      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(1)
      expect(map[-2]).to eq("x".b)
      expect(map[-3]).to eq("y".b)
      expect(map[-4]).to eq("d".b)
    end

    it "does not include labels without value" do
      key = COSE::Key::EC2.new(crv: 1, d: "d".b)

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map.keys.size).to eq(3)
      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(1)
      expect(map[-4]).to eq("d".b)
    end
  end
end
