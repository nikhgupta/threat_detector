# frozen_string_literal: true

module ThreatDetector
  class Downloader
    include ThreatDetector::Utility
    FEEDS_URL = 'https://threatfeeds.io'

    attr_reader :options

    def initialize(options = {})
      @options = sanitize_options(options)
      @cache = ThreatDetector::Cache.load(options)
    end

    def run(&block)
      fetch_feeds_json

      group_feeds_by_name.each do |name, rows|
        scraper = ThreatDetector::Scraper.new name, options
        rows.each.with_index do |row, idx|
          scraper.url = row['url']
          scraper.parse_and_save_entries { |arr| @cache.add_entries arr }

          block&.call(row['name'], idx, row, scraper)
        end
      end

      @cache.finalize!
    end

    protected

    def fetch_feeds_json
      regex = /var\s+feeds\s*=\s*(.*?);/i
      fetch_page FEEDS_URL
      match = @page.body_str.match(regex)
      raise_error 'Could not find feeds JSON' unless match

      @json = JSON.parse(match[1])
    rescue JSON::ParserError, TypeError
      raise_error 'Could not validate feeds JSON'
    end

    def group_feeds_by_name
      grouped = @json.group_by do |row|
        row['name']
      end

      grouped.map do |name, rows|
        rows = rows.select do |row|
          !row['url'].to_s.strip.empty? && row['pricing'] == 'free'
        end

        [name.parameterize.underscore, rows]
      end.to_h
    end
  end
end
