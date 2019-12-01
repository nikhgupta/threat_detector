# frozen_string_literal: true

require 'simplecov'
require 'bundler/setup'
SimpleCov.start do
  add_filter "/spec/"
end

require 'pry'
require 'threat_detector'

pattern = File.join(File.dirname(__FILE__), 'support', '**', '*.rb')
Dir.glob(pattern).each { |file| require file }

RSpec.configure do |config|
  config.include ThreatDetector::TestCase

  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = '.rspec_status'

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end
