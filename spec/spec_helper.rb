# frozen_string_literal: true

require "cbor"
require "byebug"

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
  CBOR::Tagged.new(0, [CBOR.encode(protected_headers), unprotected_headers, *args]).to_cbor
end
