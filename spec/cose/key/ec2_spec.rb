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
        -1 => 1,
        -2 => "x",
        -3 => "y",
        -4 => "d",
      )
    )

    expect(key.curve).to eq(1)
    expect(key.x_coordinate).to eq("x")
    expect(key.y_coordinate).to eq("y")
    expect(key.d_coordinate).to eq("d")
  end

  context "#to_pkey" do
    let(:original_pkey) { OpenSSL::PKey::EC.new("prime256v1").generate_key }

    let(:pkey) do
      COSE::Key::EC2.from_pkey(original_pkey).to_pkey
    end

    it "it generates an instance of OpenSSL::PKey::PKey" do
      expect(pkey).to be_a(OpenSSL::PKey::EC)
    end

    it "it generates with the correct curve" do
      expect(pkey.group.curve_name).to eq("prime256v1")
    end

    it "it generates the same public key" do
      expect(pkey.public_key).to eq(original_pkey.public_key)
    end

    it "it generates the same private key" do
      expect(pkey.private_key).to eq(original_pkey.private_key)
    end
  end
end
