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
        5 => "init-vector".b,
        4 => 1,
        3 => 0,
        2 => "id".b,
        1 => 4,
        -1 => "k"
      )
    )

    expect(key.base_iv).to eq("init-vector".b)
    expect(key.key_ops).to eq(1)
    expect(key.alg).to eq(0)
    expect(key.kid).to eq("id".b)
    expect(key.key_value).to eq("k")
  end

  context "#serialize" do
    it "works" do
      key = COSE::Key::Symmetric.new(
        kid: "id".b,
        alg: 0,
        key_ops: 1,
        base_iv: "init-vector".b,
        key_value: "key".b
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
  end
end
