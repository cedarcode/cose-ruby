# frozen_string_literal: true

require "cbor"
require "cose/key/okp"

RSpec.describe COSE::Key::OKP do
  describe ".new" do
    it "validates crv presence" do
      expect { COSE::Key::OKP.new(crv: nil) }.to raise_error("Required crv is missing")
    end

    it "validates presence of at least x or d" do
      expect { COSE::Key::OKP.new(crv: 4) }.to raise_error("x and d cannot be missing simultaneously")
    end

    it "can build a public key" do
      key = COSE::Key::OKP.new(crv: 4, x: "x".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq("x".b)
      expect(key.d).to eq(nil)
    end

    it "can build a private key without x" do
      key = COSE::Key::OKP.new(crv: 4, d: "d".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq(nil)
      expect(key.d).to eq("d".b)
    end

    it "can build a private key with x" do
      key = COSE::Key::OKP.new(crv: 4, x: "x".b, d: "d".b)

      expect(key.crv).to eq(4)
      expect(key.x).to eq("x".b)
      expect(key.d).to eq("d".b)
    end
  end

  context "#to_pkey" do
    if curve_25519_supported?
      it "works for an Ed25519 private key" do
        original_pkey = OpenSSL::PKey.generate_key("ED25519")
        pkey = COSE::Key::OKP.from_pkey(original_pkey).to_pkey

        expect(pkey).to be_a(OpenSSL::PKey::PKey)
        expect(pkey.oid).to eq("ED25519")
        expect(pkey.public_to_der).to eq(original_pkey.public_to_der)
        expect(pkey.private_to_der).to eq(original_pkey.private_to_der)
      end

      it "works for an Ed25519 public key" do
        original_pkey = OpenSSL::PKey.generate_key("ED25519")
        public_key = OpenSSL::PKey.read(original_pkey.public_to_der)
        pkey = COSE::Key::OKP.from_pkey(public_key).to_pkey

        expect(pkey).to be_a(OpenSSL::PKey::PKey)
        expect(pkey.oid).to eq("ED25519")
        expect(pkey.public_to_der).to eq(original_pkey.public_to_der)
      end

      it "works for an Ed448 private key" do
        original_pkey = OpenSSL::PKey.generate_key("ED448")
        pkey = COSE::Key::OKP.from_pkey(original_pkey).to_pkey

        expect(pkey).to be_a(OpenSSL::PKey::PKey)
        expect(pkey.oid).to eq("ED448")
        expect(pkey.public_to_der).to eq(original_pkey.public_to_der)
        expect(pkey.private_to_der).to eq(original_pkey.private_to_der)
      end

      it "works for an Ed25519 public key" do
        original_pkey = OpenSSL::PKey.generate_key("ED448")
        public_key = OpenSSL::PKey.read(original_pkey.public_to_der)
        pkey = COSE::Key::OKP.from_pkey(public_key).to_pkey

        expect(pkey).to be_a(OpenSSL::PKey::PKey)
        expect(pkey.oid).to eq("ED448")
        expect(pkey.public_to_der).to eq(original_pkey.public_to_der)
      end
    end
  end

  describe ".deserialize" do
    it "works" do
      key = COSE::Key::OKP.deserialize(
        CBOR.encode(
          5 => "init-vector".b,
          4 => 1,
          3 => 0,
          2 => "id".b,
          1 => 1,
          -1 => 4,
          -2 => "x".b,
          -4 => "d".b
        )
      )

      expect(key.base_iv).to eq("init-vector".b)
      expect(key.key_ops).to eq(1)
      expect(key.alg).to eq(0)
      expect(key.kid).to eq("id".b)
      expect(key.crv).to eq(4)
      expect(key.x).to eq("x".b)
      expect(key.d).to eq("d".b)
    end

    it "returns an error if key type is wrong" do
      expect {
        COSE::Key::OKP.deserialize(
          CBOR.encode(
            1 => 2,
            -1 => 4,
            -2 => "x".b,
          )
        )
      }.to raise_error("Not an OKP key")
    end
  end

  describe "#serialize" do
    it "works" do
      key = COSE::Key::OKP.new(
        kid: "id".b,
        alg: -7,
        key_ops: 1,
        base_iv: "init-vector".b,
        crv: 4,
        x: "x".b,
        d: "d".b
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[5]).to eq("init-vector".b)
      expect(map[4]).to eq(1)
      expect(map[3]).to eq(-7)
      expect(map[2]).to eq("id".b)
      expect(map[1]).to eq(1)
      expect(map[-1]).to eq(4)
      expect(map[-2]).to eq("x".b)
      expect(map[-4]).to eq("d".b)
    end

    it "does not include labels without value" do
      key = COSE::Key::OKP.new(crv: 4, x: "x".b)

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map.keys.size).to eq(3)
      expect(map[1]).to eq(1)
      expect(map[-1]).to eq(4)
      expect(map[-2]).to eq("x".b)
    end
  end
end
