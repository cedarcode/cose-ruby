# frozen_string_literal: true

require "base64"
require "cbor"
require "cose/algorithm"
require "cose/error"
require "cose/key"
require "cose/sign1"

RSpec.describe "COSE::Sign1" do
  context ".deserialize" do
    before do
      cbor = create_security_message({ 1 => -7 }, { 4 => "11" }, "This is the content".b, "signature".b, cbor_tag: 18)

      @sign1 = COSE::Sign1.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@sign1.protected_headers).to eq(1 => -7)
    end

    it "returns unprotected headers" do
      expect(@sign1.unprotected_headers).to eq(4 => "11")
    end

    it "returns payload" do
      expect(@sign1.payload).to eq("This is the content".b)
    end

    it "returns the signature" do
      expect(@sign1.signature).to eq("signature".b)
    end
  end

  context "#verify" do
    wg_examples("sign1-tests/*.json") do |example|
      it "passes #{example['title']}" do
        key_data = example["input"]["sign0"]["key"]

        key = COSE::Key::EC2.new(
          kid: key_data["kid"],
          alg: COSE::Algorithm.by_name(example["input"]["sign0"]["alg"]).id,
          crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
          x: Base64.urlsafe_decode64(key_data["x"]),
          y: Base64.urlsafe_decode64(key_data["y"])
        )

        external_aad = hex_to_bytes(example["input"]["sign0"]["external"])
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Sign1.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Sign1.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end

    wg_examples("ecdsa-examples/ecdsa-sig-*.json") do |example|
      it "passes #{example['title']}" do
        key_data = example["input"]["sign0"]["key"]

        key = COSE::Key::EC2.new(
          kid: key_data["kid"],
          crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
          x: Base64.urlsafe_decode64(key_data["x"]),
          y: Base64.urlsafe_decode64(key_data["y"])
        )

        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Sign1.deserialize(cbor).verify(key) }.to raise_error(COSE::Error)
        else
          expect(COSE::Sign1.deserialize(cbor).verify(key)).to be_truthy
        end
      end
    end

    if curve_25519_supported?
      wg_examples("eddsa-examples/eddsa-sig-*.json") do |example|
        it "passes #{example['title']}" do
          key_data = example["input"]["sign0"]["key"]

          key = COSE::Key::OKP.new(
            kid: key_data["kid"],
            alg: COSE::Algorithm.by_name(example["input"]["sign0"]["alg"]).id,
            crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
            x: hex_to_bytes(key_data["x_hex"]),
            d: hex_to_bytes(key_data["d_hex"])
          )

          cbor = hex_to_bytes(example["output"]["cbor"])

          if example["fail"]
            expect { COSE::Sign1.deserialize(cbor).verify(key) }.to raise_error(COSE::Error)
          else
            expect(COSE::Sign1.deserialize(cbor).verify(key)).to be_truthy
          end
        end
      end
    end
  end
end
