# frozen_string_literal: true

require "cose/key/rsa"
require "openssl"

RSpec.describe COSE::Key::RSA do
  describe ".new" do
    it "can build a public key" do
      key = COSE::Key::RSA.new(n: "n".b, e: "e".b)

      expect(key.n).to eq("n".b)
      expect(key.e).to eq("e".b)
    end

    it "can build a private key with two primes" do
      key = COSE::Key::RSA.new(
        n: "n".b,
        e: "e".b,
        d: "d".b,
        p: "p".b,
        q: "q".b,
        dp: "dP".b,
        dq: "dQ".b,
        qinv: "qInv".b
      )

      expect(key.n).to eq("n".b)
      expect(key.e).to eq("e".b)
      expect(key.d).to eq("d".b)
      expect(key.p).to eq("p".b)
      expect(key.q).to eq("q".b)
      expect(key.dp).to eq("dP".b)
      expect(key.dq).to eq("dQ".b)
      expect(key.qinv).to eq("qInv".b)
    end

    it "validates presence of all public key fields" do
      expect {
        COSE::Key::RSA.new(n: "n".b, e: nil)
      }.to raise_error("Required public field e is missing")

      expect {
        COSE::Key::RSA.new(n: nil, e: "e".b)
      }.to raise_error("Required public field n is missing")
    end

    it "validates presence of all private key fields" do
      private_fields = {
        d: "d".b,
        p: "p".b,
        q: "q".b,
        dp: "dP".b,
        dq: "dQ".b,
        qinv: "qInv".b
      }

      public_fields = {
        n: "n".b,
        e: "e".b
      }

      valid_arguments = public_fields.merge(private_fields)

      private_fields.each do |k, _v|
        invalid_arguments = valid_arguments.dup
        invalid_arguments[k] = nil

        expect { COSE::Key::RSA.new(**invalid_arguments) }.to raise_error("Incomplete private fields, #{k} is missing")
      end
    end
  end

  describe ".deserialize" do
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

    it "works" do
      key = COSE::Key::RSA.deserialize(
        CBOR.encode(
          5 => "init-vector".b,
          4 => 1,
          3 => -37,
          2 => "id".b,
          1 => 3,
          -1 => "n".b,
          -2 => "e".b,
          -3 => "d".b,
          -4 => "p".b,
          -5 => "q".b,
          -6 => "dP".b,
          -7 => "dQ".b,
          -8 => "qInv".b
        )
      )

      expect(key.base_iv).to eq("init-vector".b)
      expect(key.key_ops).to eq(1)
      expect(key.alg).to eq(-37)
      expect(key.kid).to eq("id".b)
      expect(key.n).to eq("n".b)
      expect(key.e).to eq("e".b)
      expect(key.d).to eq("d".b)
      expect(key.p).to eq("p".b)
      expect(key.q).to eq("q".b)
      expect(key.dp).to eq("dP".b)
      expect(key.dq).to eq("dQ".b)
      expect(key.qinv).to eq("qInv".b)
    end
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
        n: "n".b,
        e: "e".b,
        d: "d".b,
        p: "p".b,
        q: "q".b,
        dp: "dP".b,
        dq: "dQ".b,
        qinv: "qInv".b
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[5]).to eq("init-vector".b)
      expect(map[4]).to eq(1)
      expect(map[3]).to eq(-37)
      expect(map[2]).to eq("id".b)
      expect(map[1]).to eq(3)
      expect(map[-1]).to eq("n".b)
      expect(map[-2]).to eq("e".b)
      expect(map[-3]).to eq("d".b)
      expect(map[-4]).to eq("p".b)
      expect(map[-5]).to eq("q".b)
      expect(map[-6]).to eq("dP".b)
      expect(map[-7]).to eq("dQ".b)
      expect(map[-8]).to eq("qInv".b)
    end

    it "does not include labels without value" do
      key = COSE::Key::RSA.new(n: "n".b, e: "e".b)

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map.keys.size).to eq(3)
      expect(map[1]).to eq(3)
      expect(map[-1]).to eq("n".b)
      expect(map[-2]).to eq("e".b)
    end
  end
end
