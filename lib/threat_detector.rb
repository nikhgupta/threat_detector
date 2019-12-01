# frozen_string_literal: true

require 'csv'
require 'curb'
require 'yaml'
require 'json'
require 'nokogiri'
require 'ipaddress'
require 'digest/md5'
require 'rambling/trie'
require 'active_support/inflector'

require 'threat_detector/version'
require 'threat_detector/utility'
require 'threat_detector/scraper'
require 'threat_detector/cache'
require 'threat_detector/downloader'
require 'threat_detector/search'

# Check IPs, Hosts, Networks or URLs for possible threats using feeds from
# ThreatFeeds.io
#
# ThreatDetector creates a local cache of threats by downloading ThreatFeeds.io
# feeds, parsing them, and storing them in
# [Trie](https://en.wikipedia.org/wiki/Trie) structures to allow for efficient
# and fast searches in this huge database of threats.
#
# ThreatDetector tries to be smart in understanding that the database may not
# necessarily contain the exact search term, and often, employs logic in
# deciding whether a given IP, network, host or URL is a threat. For example,
# in addition to directly matching threats in this database, it knows that:
#
# - An IP is a threat if it belongs to an identified network.
# - A network is a threat if it belongs to a wider identified network.
# - An IP is a threat if the hostname it resolves to is marked as a threat.
# - A host can be a threat if the IP it resolves to is marked as a threat.
# - A url can be a threat if its hostname or IP is marked as a threat.
# - etc.
#
# Furthermore, any threat that is identified is returned with a reason for the
# same, allowing you to also identify why a particular IP, host, network or URL
# was marked as a threat. You can, optionally, choose to disable smarter
# searching (only match directly with database), disable resolving IP/host to
# corresponding host/IP for matching, etc.
module ThreatDetector
  # Base error class for this gem.
  #
  # Any errors raised and recognized by this gem # are instances of this class.
  class Error < StandardError; end

  # Root path for this gem.
  ROOT = File.dirname(File.dirname(__FILE__))

  # Directory where downloaded feeds and cache will be saved by default.
  # You can specify another directory to save the feeds and cache, by using
  # `:working_directory` option when instantiating {ThreatDetector::Scraper} or
  # {ThreatDetector::Downloader}. Note that, you must also specify this option
  # when instanting {ThreatDetector::Search} in this case.
  DEFAULT_HOME = File.join(ENV['HOME'], '.threat_detector')

  # Path to default scraping configuration YAML file.
  # This configuration is used by {ThreatDetector::Scraper#parse}, and can be
  # changed to another file by using `:feeds_config_path` option when instantiating
  # {ThreatDetector::Scraper} or {ThreatDetector::Downloader}
  DEFAULT_CONFIG = File.join(ROOT, 'feeds.yaml')

  # Default User Agent for scrapers.
  USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'

  # Default CURL options used by scrapers, used by {ThreatDetector::Utility#fetch_page}
  # They can be overridden by passing relevant options when fetching the page. These options
  # are passed to Curb library.
  # @see https://github.com/taf2/curb Curb Library ReadMe
  DEFAULT_CURL_OPTIONS = {
    timeout: 30,
    encoding: 'gzip',
    max_redirects: 10,
    follow_location: true,
    useragent: USER_AGENT
  }.freeze

  # Helper method to instantiate {ThreatDetector::Downloader} with given options,
  # and run the downloader afterwards.
  #
  # @see ThreatDetector::Downloader#initialize reference for options
  # @see ThreatDetector::Downloader#run reference for block
  def self.download(options = {}, &block)
    ThreatDetector::Downloader.new(options).run(&block)
  end

  # Helper method to instantiate {ThreatDetector::Cache} with given options,
  # and run the cache builder afterwards.
  #
  # @see ThreatDetector::Cache#initialize reference for options
  # @see ThreatDetector::Cache#run reference for block
  def self.build_cache(options = {}, &block)
    ThreatDetector::Cache.new(options).run(&block)
  end

  # Helper method to instantiate {ThreatDetector::Search} with given options,
  # and run the search on specified keys afterwards.
  #
  # @param (see ThreatDetector::Search#initialize)
  # @param (see ThreatDetector::Search#run)
  # @param [Array{String,#read}] keys search terms or files with search terms
  #
  # @yield (see ThreatDetector::Search#run)
  # @yieldparam (see ThreatDetector::Search#run)
  # @yieldreturn (see ThreatDetector::Search#run)
  # @return (see ThreatDetector::Search#run)
  def self.search(keys, options = {}, &block)
    ThreatDetector::Search.new(options).process(*keys, &block)
  end
end
