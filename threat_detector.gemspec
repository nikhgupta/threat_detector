# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'threat_detector/version'

Gem::Specification.new do |spec|
  spec.name          = 'threat_detector'
  spec.version       = ThreatDetector::VERSION
  spec.authors       = ['nikhgupta']
  spec.email         = ['me@nikhgupta.com']

  spec.summary       = 'Detect whether an ip, host or url is identified as threat via ThreatFeeds.io'
  spec.description   = 'Detect whether an ip, host or url is identified as threat via ThreatFeeds.io'
  spec.homepage      = 'https://github.com/nikhgupta/threat_detector'
  spec.license       = 'MIT'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files         = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.17'
  spec.add_development_dependency 'rake', '~> 10.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'vcr'
  spec.add_development_dependency 'webmock'
  spec.add_development_dependency 'pry'

  spec.add_dependency 'activesupport', '~> 6.0'
  spec.add_dependency 'curb', '~> 0.9'
  spec.add_dependency 'ipaddress', '~> 0.8'
  spec.add_dependency 'nokogiri', '~> 1.10'
  spec.add_dependency 'rambling-trie', '~> 2.1'
  spec.add_dependency 'thor', '~> 0.20.3'
end
