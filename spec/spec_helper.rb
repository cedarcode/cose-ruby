# frozen_string_literal: true

require "bundler/setup"
require "cbor"
require "cose"

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

def create_security_message(protected_headers, unprotected_headers, *args)
  CBOR.encode([CBOR.encode(protected_headers), unprotected_headers, *args])
end
