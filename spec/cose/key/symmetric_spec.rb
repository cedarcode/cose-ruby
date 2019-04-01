# frozen_string_literal: true

require "cbor"
require "cose/key/symmetric"

RSpec.describe COSE::Key::Symmetric do
  describe ".new" do
    it "validates k presence" do
      expect { COSE::Key::Symmetric.new(k: nil) }.to raise_error("Required key value k is missing")
    end
  end

  describe ".deserialize" do
    it "works" do
      key = COSE::Key::Symmetric.deserialize(
        CBOR.encode(
          5 => "init-vector".b,
          4 => 1,
          3 => 0,
          2 => "id".b,
          1 => 4,
          -1 => "k".b
        )
      )

      expect(key.base_iv).to eq("init-vector".b)
      expect(key.key_ops).to eq(1)
      expect(key.alg).to eq(0)
      expect(key.kid).to eq("id".b)
      expect(key.k).to eq("k".b)
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
  end

  context "#serialize" do
    it "works" do
      key = COSE::Key::Symmetric.new(
        kid: "id".b,
        alg: 0,
        key_ops: 1,
        base_iv: "init-vector".b,
        k: "key".b
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[5]).to eq("init-vector".b)
      expect(map[4]).to eq(1)
      expect(map[3]).to eq(0)
      expect(map[2]).to eq("id".b)
      expect(map[1]).to eq(4)
      expect(map[-1]).to eq("key".b)
    end

    it "does not include labels without value" do
      key = COSE::Key::Symmetric.new(k: "k".b)

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map.keys.size).to eq(2)
      expect(map[1]).to eq(4)
      expect(map[-1]).to eq("k".b)
    end
  end
end
