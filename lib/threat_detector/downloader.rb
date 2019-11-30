# frozen_string_literal: true

module ThreatDetector
  # Download feeds from ThreatFeeds, and scrape them synchronously.
  #
  # Path where feed entries will be saved can be provided, along with
  # scraping configuration for various feed URLs. Please, look into
  # `ThreatDetector::Scraper` to read more about scraping configuration.
  #
  class Downloader
    include ThreatDetector::Utility
    FEEDS_URL = 'https://threatfeeds.io'

    attr_reader :options

    def initialize(options = {})
      @options = sanitize_options(options)
      @cache = ThreatDetector::Cache.load(options)
    end

    # Fetch feeds as JSON data from ThreatFeeds.io, and scrape them.
    #
    # Entries from each feed are saved into subsets in our local cache.
    # Afterwards, we freeze our cache to make sure its not mutable.
    #
    # We can pass a block to this method to further work with the scraper.
    #
    def run
      fetch_feeds_json FEEDS_URL
      scraper = ThreatDetector::Scraper.new options

      @json.each do |row|
        next unless valid_feed?(row)

        scraper.reset!(row['name'], row['url'])
        scraper.parse_and_save_entries { |arr| @cache.add_entries arr }

        yield(row['name'], row, scraper) if block_given?
      end

      @cache.finalize!
    end

    protected

    def fetch_feeds_json(url)
      fetch_page url
      regex = /var\s+feeds\s*=\s*(.*?);/i
      match = @page.body_str.match(regex)
      raise_error 'Could not find feeds JSON' unless match

      @json = JSON.parse(match[1])
    rescue JSON::ParserError, TypeError
      raise_error 'Could not validate feeds JSON'
    end

    def valid_feed?(row)
      return false if row['url'].to_s.strip.empty?

      row['pricing'] == 'free'
    end
  end
end
