# frozen_string_literal: true

require "base64"
require "cbor"
require "cose/key"
require "cose/sign"
require "cose/signature"

RSpec.describe "COSE::Sign" do
  context ".deserialize" do
    before do
      cbor = create_security_message(
        { 1 => 2 },
        { 3 => 4 },
        "This is the content".b,
        [
          [CBOR.encode({ 5 => 6 }), { 7 => 8 }, "signatureA".b],
          [CBOR.encode({ 9 => 10 }), { 11 => 12 }, "signatureB".b]
        ],
        cbor_tag: 98
      )

      @sign = COSE::Sign.deserialize(cbor)
    end

    it "returns protected headers" do
      expect(@sign.protected_headers).to eq(1 => 2)
    end

    it "returns unprotected headers" do
      expect(@sign.unprotected_headers).to eq(3 => 4)
    end

    it "returns payload" do
      expect(@sign.payload).to eq("This is the content".b)
    end

    it "returns the signatures" do
      expect(@sign.signatures.size).to eq(2)
      expect(@sign.signatures.all? { |s| s.is_a?(COSE::Signature) }).to be_truthy
    end
  end

  context "#verify" do
    wg_examples("sign-tests/*.json") do |example|
      it "passes #{example['title']}" do
        signer_data = example["input"]["sign"]["signers"][0]
        key_data = signer_data["key"]

        key = COSE::Key::EC2.new(
          kid: key_data["kid"],
          crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
          x: Base64.urlsafe_decode64(key_data["x"]),
          y: Base64.urlsafe_decode64(key_data["y"])
        )

        external_aad = hex_to_bytes(signer_data["external"])
        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Sign.deserialize(cbor).verify(key, external_aad) }.to raise_error(COSE::Error)
        else
          expect(COSE::Sign.deserialize(cbor).verify(key, external_aad)).to be_truthy
        end
      end
    end

    wg_examples("ecdsa-examples/ecdsa-0*.json") do |example|
      it "passes #{example['title']}" do
        key_data = example["input"]["sign"]["signers"][0]["key"]

        key = COSE::Key::EC2.new(
          kid: key_data["kid"],
          crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
          x: Base64.urlsafe_decode64(key_data["x"]),
          y: Base64.urlsafe_decode64(key_data["y"])
        )

        cbor = hex_to_bytes(example["output"]["cbor"])

        if example["fail"]
          expect { COSE::Sign.deserialize(cbor).verify(key) }.to raise_error(COSE::Error)
        else
          expect(COSE::Sign.deserialize(cbor).verify(key)).to be_truthy
        end
      end
    end

    if curve_25519_supported?
      wg_examples("eddsa-examples/eddsa-0*.json") do |example|
        it "passes #{example['title']}" do
          key_data = example["input"]["sign"]["signers"][0]["key"]

          key = COSE::Key::OKP.new(
            kid: key_data["kid"],
            crv: COSE::Key::Curve.by_name(key_data["crv"]).id,
            x: hex_to_bytes(key_data["x_hex"]),
            d: hex_to_bytes(key_data["d_hex"])
          )

          cbor = hex_to_bytes(example["output"]["cbor"])

          if example["fail"]
            expect { COSE::Sign.deserialize(cbor).verify(key) }.to raise_error(COSE::Error)
          else
            expect(COSE::Sign.deserialize(cbor).verify(key)).to be_truthy
          end
        end
      end
    end

    if rsa_pss_supported?
      wg_examples("rsa-pss-examples/*.json") do |example|
        it "passes #{example['title']}" do
          key_data = example["input"]["sign"]["signers"][0]["key"]

          key = COSE::Key::RSA.new(
            kid: key_data["kid"],
            n: hex_to_bytes(key_data["n_hex"]),
            e: hex_to_bytes(key_data["e_hex"])
          )

          cbor = hex_to_bytes(example["output"]["cbor"])

          if example["fail"]
            expect { COSE::Sign.deserialize(cbor).verify(key) }.to raise_error(COSE::Error)
          else
            expect(COSE::Sign.deserialize(cbor).verify(key)).to be_truthy
          end
        end
      end
    end
  end
end
