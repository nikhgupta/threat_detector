# frozen_string_literal: true

require 'pry'
require 'curb'
require 'yaml'
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

module ThreatDetector
  class Error < StandardError; end

  ROOT = File.dirname(File.dirname(__FILE__))
  DEFAULT_CONFIG = File.join(ROOT, 'feeds.yaml')
  DEFAULT_HOME = File.join(ENV['HOME'], '.threat_detector')
  USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'

  DEFAULT_CURL_OPTIONS = {
    timeout: 20,
    encoding: 'gzip',
    max_redirects: 10,
    follow_location: true,
    useragent: USER_AGENT
  }.freeze

  def self.download(options = {}, &block)
    ThreatDetector::Downloader.new(options).run(&block)
  end

  def self.build_cache(options = {}, &block)
    ThreatDetector::Cache.new(options).run(&block)
  end

  def self.search(keys, options = {}, &block)
    ThreatDetector::Search.new(options).run(keys, &block)
  end
end
