# frozen_string_literal: true

require 'vcr'

VCR.configure do |config|
  config.hook_into :webmock
  config.cassette_library_dir = 'spec/cassettes'
  config.default_cassette_options = { record: :new_episodes }

  config.configure_rspec_metadata!
  config.allow_http_connections_when_no_cassette = true
end
