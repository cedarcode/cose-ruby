# frozen_string_literal: true

require "cose/key/ec2"

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

  it "can decode CBOR" do
    key = COSE::Key::EC2.from_cbor(
      CBOR.encode(
        1 => 2,
        -1 => 1,
        -2 => "x",
        -3 => "y"
      )
    )

    expect(key.curve).to eq(1)
    expect(key.x_coordinate).to eq("x")
    expect(key.y_coordinate).to eq("y")
  end
end
