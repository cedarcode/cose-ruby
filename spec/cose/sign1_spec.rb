# frozen_string_literal: true

require "base64"
require "cbor"
require "cose/algorithm"
require "cose/error"
require "cose/key"
require "cose/sign1"
require "openssl"

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

    # TODO: Test against ecdsa-examples/ecdsa-sig-04.json when we support implicit curve
    wg_examples("ecdsa-examples/ecdsa-sig-0{1,2,3}.json") do |example|
      it "passes #{example['title']}" do
        key_data = example["input"]["sign0"]["key"]

        key = COSE::Key::EC2.new(
          kid: key_data["kid"],
          alg: COSE::Algorithm.by_name(example["input"]["sign0"]["alg"]).id,
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

    it "raises COSE::Error, not OpenSSL::SignatureAlgorithm::VerifyKeyError, when the key's curve " \
       "doesn't match the header alg's curve" do
      key = COSE::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate("prime256v1")) # P-256

      # ES384 (alg -35) expects a P-384 key; verifying with a P-256 key must not leak the
      # underlying openssl-signature_algorithm VerifyKeyError.
      cbor = create_security_message({ 1 => -35 }, {}, "content".b, "signature".b, cbor_tag: 18)

      expect { COSE::Sign1.deserialize(cbor).verify(key) }.to raise_error(COSE::Error, "Signature verification failed")
    end
  end

  context "#sign and #serialize" do
    {
      "ES256" => "prime256v1",
      "ES384" => "secp384r1",
      "ES512" => "secp521r1"
    }.each do |alg_name, curve_name|
      it "signs, serializes, deserializes and verifies a round trip for #{alg_name}" do
        algorithm = COSE::Algorithm.by_name(alg_name)
        key = COSE::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate(curve_name))

        sign1 = COSE::Sign1.new(
          protected_headers: { 1 => algorithm.id },
          unprotected_headers: {},
          payload: "This is the content".b
        )

        expect(sign1.sign(key)).to be(sign1)
        expect(sign1.signature).to be_a(String)

        deserialized = COSE::Sign1.deserialize(sign1.serialize)

        expect(deserialized.protected_headers).to eq(1 => algorithm.id)
        expect(deserialized.payload).to eq("This is the content".b)
        expect(deserialized.verify(key)).to be(true)
      end
    end

    if curve_25519_supported?
      it "signs, serializes, deserializes and verifies a round trip for EdDSA" do
        algorithm = COSE::Algorithm.by_name("EdDSA")
        key = COSE::Key::OKP.from_pkey(OpenSSL::PKey.generate_key("ED25519"))

        sign1 = COSE::Sign1.new(
          protected_headers: { 1 => algorithm.id },
          unprotected_headers: {},
          payload: "This is the content".b
        )

        sign1.sign(key)

        deserialized = COSE::Sign1.deserialize(sign1.serialize)

        expect(deserialized.verify(key)).to be(true)
      end
    end

    if rsa_pss_supported?
      it "signs, serializes, deserializes and verifies a round trip for PS256" do
        algorithm = COSE::Algorithm.by_name("PS256")
        key = COSE::Key::RSA.from_pkey(OpenSSL::PKey::RSA.new(2048))

        sign1 = COSE::Sign1.new(
          protected_headers: { 1 => algorithm.id },
          unprotected_headers: {},
          payload: "This is the content".b
        )

        sign1.sign(key)

        deserialized = COSE::Sign1.deserialize(sign1.serialize)

        expect(deserialized.verify(key)).to be(true)
      end
    end

    it "supports signing and verifying with a detached payload" do
      algorithm = COSE::Algorithm.by_name("ES256")
      key = COSE::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate("prime256v1"))
      detached_payload = "Detached content, not embedded in the message".b

      signing_message = COSE::Sign1.new(
        protected_headers: { 1 => algorithm.id },
        unprotected_headers: {},
        payload: detached_payload
      )
      signing_message.sign(key)

      sign1 = COSE::Sign1.new(
        protected_headers: { 1 => algorithm.id },
        unprotected_headers: {},
        payload: nil,
        signature: signing_message.signature
      )

      deserialized = COSE::Sign1.deserialize(sign1.serialize)

      expect(deserialized.payload).to be_nil
      expect(deserialized.verify(key, detached_payload: detached_payload)).to be(true)
      expect { deserialized.verify(key) }.to raise_error(COSE::Error)
    end

    it "raises COSE::Error when serializing before signing" do
      sign1 = COSE::Sign1.new(
        protected_headers: { 1 => COSE::Algorithm.by_name("ES256").id },
        unprotected_headers: {},
        payload: "content".b
      )

      expect { sign1.serialize }.to raise_error(COSE::Error)
    end

    it "raises COSE::Error when signing with a public-only key" do
      algorithm = COSE::Algorithm.by_name("ES256")
      private_key = COSE::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate("prime256v1"))
      public_key = COSE::Key::EC2.new(crv: private_key.crv, x: private_key.x, y: private_key.y)

      sign1 = COSE::Sign1.new(
        protected_headers: { 1 => algorithm.id },
        unprotected_headers: {},
        payload: "content".b
      )

      expect { sign1.sign(public_key) }.to raise_error(COSE::Error)
    end

    it "raises COSE::Error when signing with a key whose curve doesn't match the header alg's curve" do
      algorithm = COSE::Algorithm.by_name("ES384") # expects a P-384 key
      key = COSE::Key::EC2.from_pkey(OpenSSL::PKey::EC.generate("prime256v1")) # P-256

      sign1 = COSE::Sign1.new(
        protected_headers: { 1 => algorithm.id },
        unprotected_headers: {},
        payload: "content".b
      )

      expect { sign1.sign(key) }.to raise_error(COSE::Error, "Incompatible key for algorithm")
    end
  end
end
