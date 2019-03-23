# frozen_string_literal: true

lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "cose/version"

Gem::Specification.new do |spec|
  spec.name          = "cose"
  spec.version       = COSE::VERSION
  spec.authors       = ["Gonzalo Rodriguez", "Braulio Martinez"]
  spec.email         = ["gonzalo@cedarcode.com", "braulio@cedarcode.com"]

  spec.summary       = "CBOR Object Signing and Encryption (COSE) ruby library"
  spec.homepage      = "https://github.com/cedarcode/cose-ruby"
  spec.license       = "MIT"

  spec.metadata = {
    "bug_tracker_uri" => "https://github.com/cedarcode/cose-ruby/issues",
    "changelog_uri" => "https://github.com/cedarcode/cose-ruby/blob/master/CHANGELOG.md",
    "source_code_uri" => "https://github.com/cedarcode/cose-ruby"
  }

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path('..', __FILE__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = ">= 2.2"

  spec.add_dependency "cbor", "~> 0.5.9.2"

  spec.add_development_dependency "appraisal", "~> 2.2.0"
  spec.add_development_dependency "bundler", ">= 1.17", "< 3"
  spec.add_development_dependency "byebug", "~> 11.0"
  spec.add_development_dependency "rake", "~> 12.3"
  spec.add_development_dependency "rspec", "~> 3.8"
  spec.add_development_dependency "rubocop", "0.65.0"
end
