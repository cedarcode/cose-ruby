# frozen_string_literal: true

require "cbor"
require "byebug"
require "json"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def create_security_message(protected_headers, unprotected_headers, *args, cbor_tag: 0)
  CBOR::Tagged.new(cbor_tag, [CBOR.encode(protected_headers), unprotected_headers, *args]).to_cbor
end

def wg_examples(relative_glob)
  Dir.glob(File.expand_path("fixtures/cose-wg-examples/#{relative_glob}", __dir__)) do |file_name|
    yield JSON.parse(File.read(file_name))
  end
end

def rsa_pss_supported?
  OpenSSL::PKey::RSA.instance_methods.include?(:verify_pss)
end

def curve_25519_supported?
  OpenSSL::OPENSSL_VERSION_NUMBER >= 0x10101000 && # >= v1.1.1
    defined?(OpenSSL::PKey.generate_key)
end

def hex_to_bytes(hex_string)
  [hex_string].pack("H*")
end
