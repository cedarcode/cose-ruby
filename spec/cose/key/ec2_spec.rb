# frozen_string_literal: true

require "cose/key/ec2"
require "openssl"

RSpec.describe COSE::Key::EC2 do
  it "returns an error if crv is missing" do
    expect {
      COSE::Key::EC2.new(curve: nil, x_coordinate: "x", y_coordinate: "y")
    }.to raise_error(ArgumentError, "Required curve is missing")
  end

  it "returns an error if x is missing" do
    expect {
      COSE::Key::EC2.new(curve: 1, x_coordinate: nil, y_coordinate: "y")
    }.to raise_error(ArgumentError, "Required x-coordinate is missing")
  end

  it "returns an error if y is missing" do
    expect {
      COSE::Key::EC2.new(curve: 1, x_coordinate: "x", y_coordinate: nil)
    }.to raise_error(ArgumentError, "Required y-coordinate is missing")
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

  it "can decode CBOR" do
    key = COSE::Key::EC2.deserialize(
      CBOR.encode(
        1 => 2,
        3 => -7,
        -1 => 1,
        -2 => "x",
        -3 => "y",
        -4 => "d",
      )
    )

    expect(key.algorithm).to eq(-7)
    expect(key.curve).to eq(1)
    expect(key.x_coordinate).to eq("x")
    expect(key.y_coordinate).to eq("y")
    expect(key.d_coordinate).to eq("d")
  end

  context "#to_pkey" do
    it "works for a P-256 key" do
      original_pkey = OpenSSL::PKey::EC.new("prime256v1").generate_key
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("prime256v1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end

    it "works for a P-384 key" do
      original_pkey = OpenSSL::PKey::EC.new("secp384r1").generate_key
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("secp384r1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end

    it "works for a P-521 key" do
      original_pkey = OpenSSL::PKey::EC.new("secp521r1").generate_key
      pkey = COSE::Key::EC2.from_pkey(original_pkey).to_pkey

      expect(pkey).to be_a(OpenSSL::PKey::EC)
      expect(pkey.group.curve_name).to eq("secp521r1")
      expect(pkey.public_key).to eq(original_pkey.public_key)
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end
  end

  context "#serialize" do
    it "works" do
      key = COSE::Key::EC2.new(
        algorithm: -7,
        curve: 1,
        x_coordinate: "x",
        y_coordinate: "y",
        d_coordinate: "d"
      )

      serialized_key = key.serialize

      map = CBOR.decode(serialized_key)

      expect(map[3]).to eq(-7)
      expect(map[1]).to eq(2)
      expect(map[-1]).to eq(1)
      expect(map[-2]).to eq("x")
      expect(map[-3]).to eq("y")
      expect(map[-4]).to eq("d")
    end
  end
end
