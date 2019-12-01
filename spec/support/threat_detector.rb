# frozen_string_literal: true

module ThreatDetector
  module TestCase
    def stub_scraper_for(downloader)
      scraper = ThreatDetector::Scraper.new(downloader.options)
      allow(ThreatDetector::Scraper).to receive(:new)
        .with(downloader.options).and_return(scraper)

      scraper
    end

    def stub_feeds_for(downloader)
      items = downloader.fetch_feeds
      items = items.select { |item| item['name'] == valid_feed }
      allow(downloader).to receive(:fetch_feeds).and_return(items)
    end

    def stub_scraper_and_feeds_for(downloader)
      stub_feeds_for(downloader)
      stub_scraper_for(downloader)
    end
  end
end
