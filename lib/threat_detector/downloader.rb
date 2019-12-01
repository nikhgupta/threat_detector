# frozen_string_literal: true

module ThreatDetector
  # Download feeds from ThreatFeeds, and scrape them synchronously.
  #
  # Path where feed entries will be saved can be provided, along with
  # scraping configuration for various feed URLs. Please, look into
  # {ThreatDetector::Scraper} to read more about scraping configuration.
  #
  # At the moment, only feeds from ThreatFeeds.io are parsed, but functionality
  class Downloader
    include ThreatDetector::Utility

    # Mapping of online threat sources.
    #
    # This is used by {#fetch_feeds} to map these sources to a method
    # for fetching list of feeds from these online sources.
    SOURCES = {
      threatfeeds: 'https://threatfeeds.io'
    }.freeze

    attr_reader :options

    # Instantiate a new {ThreatDetector::Downloader}
    #
    # @param  (see ThreatDetector::Utility#sanitize_options)
    # @option opts [String] :working_directory directory to download feeds and build cache in
    # @option opts [String] :feeds_config_path path to YAML file with scraping config
    #
    # The default options are:
    #   working_directory: ~/.threat_detector
    #   feeds_config_path: <gem_path>/threat_detector/feeds.yaml
    def initialize(options = {})
      @options = sanitize_options(options)
    end

    # Download list of threats from provided online sources by scraping them.
    # First a list of feeds is compiled from online sources, after which each
    # feed is scraped for threat entries.
    #
    # @yield [item, scraper] iterator for a feed and scraper after scraping
    # @yieldparam [Hash] item feed item from online sources with name, url and source
    # @yieldparam [ThreatDetector::Scraper] scraper scraper instance after scraping has been performed
    # @return [Array<Hash>] array of feed items with name, url and source
    #
    # @note The scraper instance being yielded has entries scraped from the feed,
    #   or otherwise, contains the reason for not having any entries.
    def run
      scraper = ThreatDetector::Scraper.new options

      fetch_feeds.map do |item|
        next unless valid_feed?(item)

        scraper.for(item['name'], item['url'])
        scraper.parse_and_save_entries

        yield(item, scraper) if block_given?
        item.slice('name', 'url', 'source')
      end.compact
    end

    # Fetch a list of feeds from each online source available to us.
    # Each online source is fed to a custom method for handling that
    # particular online source.
    #
    # @raise [ThreatDetector::Error] when feeds JSON can't be found or parsed
    # @return [Array<Hash>] list of feed items with details from online sources
    #
    # @note {ThreatDetector::Error} is raised whenever we receive errors from
    #   parsing underlying online sources.
    def fetch_feeds
      SOURCES.keys.map do |name|
        items = send "fetch_feeds_from_#{name}"
        items.map { |item| item.merge('source' => name.to_s) }
      end.flatten(1)
    end

    # Fetch a list of feeds from ThreatFeeds.io
    # @return [Array<Hash>] list of feeds items found on ThreatFeeds.io
    # @raise [ThreatDetector::Error] when feeds JSON can't be found or parsed
    # @see #fetch_feeds
    def fetch_feeds_from_threatfeeds
      fetch_page SOURCES[:threatfeeds]
      regex = /var\s+feeds\s*=\s*(.*?);/i
      match = @page.body_str.match(regex)
      raise_error 'Could not find feeds JSON for ThreatFeeds.io' unless match

      items = JSON.parse(match[1])
      items.select { |item| item['pricing'] == 'free' }
    rescue JSON::ParserError, TypeError
      raise_error 'Could not validate feeds JSON for ThreatFeeds.io'
    end

    protected

    # Check whether a given feed contains valid data.
    # This is a naive implementation at the moment, but can be useful in future
    # for other online sources.
    def valid_feed?(item)
      !item['url'].to_s.strip.empty?
    end
  end
end
