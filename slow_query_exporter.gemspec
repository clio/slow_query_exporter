# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'slow_query_exporter/version'

Gem::Specification.new do |spec|
  spec.name          = "slow_query_exporter"
  spec.version       = SlowQueryExporter::VERSION
  spec.authors       = ["Dennis Taylor"]
  spec.email         = ["dennis.taylor@clio.com"]

  spec.summary       = %q{A daemon which exports MySQL slow query logs to Graylog.}
  spec.homepage      = "https://github.com/fimmtiu/slow_query_exporter"
  spec.license       = "MIT"

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  if spec.respond_to?(:metadata)
    spec.metadata['allowed_push_host'] = "nope"
  else
    raise "RubyGems 2.0 or newer is required to protect against public gem pushes."
  end

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.10"
  spec.add_development_dependency "rake", "~> 10.0"

  spec.add_runtime_dependency "pentagram", "~> 2.0"
  spec.add_runtime_dependency "digest-crc", "~> 0.4"
  spec.add_runtime_dependency "gelf", "~> 3.0"
end
