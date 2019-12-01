# frozen_string_literal: true

RSpec.describe ThreatDetector::Scraper, :vcr do
  let(:work_dir) { File.join(ThreatDetector::ROOT, 'tmp') }
  subject { described_class.new(working_directory: work_dir) }
  let(:feeds) { ThreatDetector::Downloader.new(subject.options).fetch_feeds }

  def expect_ip(str)
    expect do
      ip = IPAddress.parse(str)
      expect(ip.address).to eq str
    end.not_to raise_error
  end

  def reset_scraper_for(name)
    feed = feeds.detect { |item| item['name'] == name }
    subject.for(feed['name'], feed['url'] + "\n")
  end

  it 'defaults to directory inside user home for working directory' do
    scraper = described_class.new
    work_dir = scraper.working_directory
    expect(work_dir).to eq File.join(ENV['HOME'], '.threat_detector')
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'allows specifying a custom working directory' do
    work_dir = subject.working_directory
    expect(work_dir).to eq work_dir
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'resets internal state when instantiated' do
    expect(subject.url).to be_nil.or be_empty
    expect(subject.name).to be_nil.or be_empty
    expect(subject.entries).to be_empty

    expect(subject.reason).to be_nil
    expect(subject.config).to be_empty
  end

  context '#parse' do
    it 'scrapes threat data for feeds' do
      reset_scraper_for('Monero Miner')
      subject.refresh = true
      subject.parse

      expect(subject).not_to be_empty
      expect(subject.reason).to be_nil
      expect(subject.config).not_to be_empty
      expect(subject.entries.size).to eq 39
      expect(subject.entries).to include('webcoin.me')

      expect(subject.name).to eq 'monero_miner'
      expect(subject.url).to eq subject.url.strip
    end

    it 'does not scrape data for feed already scraped' do
      reset_scraper_for('Monero Miner')
      subject.parse_and_save_entries # cache entries locally atleast once
      path = File.join(subject.working_directory, 'feeds', 'monero_miner-535f3d7a5.txt')
      expect(File.exist?(path)).to be_truthy

      # on re-scraping, we should not fetch new data
      reset_scraper_for('Monero Miner')
      subject.parse

      expect(subject).to be_empty
      expect(subject).to be_configured
      expect(subject.reason).to eq 'Found cached entries'
      expect(subject.entries).to be_empty
      expect(subject.config).not_to be_empty
    end

    # We want to scrape whatever entries, we can.
    # If you want to check whether a given feed is valid, you can check
    # using `#configured?` method, which checks for existing of feed
    # in configured scraping settings inside `:feeds_config_path` YAML.
    it 'does not raise errors when feed with invalid data is scraped' do
      subject.for('Invalid Feed', 'http://example.com')
      subject.parse

      expect(subject).not_to be_empty
      expect(subject).not_to be_configured
      expect(subject.config).to be_empty
      expect(subject.entries).not_to be_empty
    end

    it 'does not scrape entries for pages with invalid response' do
      subject.for('Invalid Page', 'http://example.com')

      allow(subject).to receive(:fetch_page).and_return nil
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'Invalid page response'

      page = double
      allow(subject).to receive(:fetch_page).and_return page
      allow(page).to receive(:response_code).and_return 401
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'Invalid page response'

      allow(subject).to receive(:fetch_page).and_return nil
      allow(page).to receive(:response_code).and_return 200
      allow(page).to receive(:body_str).and_return ''
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'Invalid page response'
    end

    it 'adds a reason when scraping is skipped due to malformed URL for feed' do
      subject.for('Invalid Page', 'http://example.com')
      allow(subject).to receive(:fetch_page).and_raise Curl::Err::MalformedURLError
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'Malformed URL passed'
    end

    it 'adds a reason when scraping is skipped due to timeout when fetching feed' do
      subject.for('Invalid Page', 'http://example.com')
      allow(subject).to receive(:fetch_page).and_raise Curl::Err::TimeoutError
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'Timeout received'
    end
  end

  context '#parse_simple_malware_list' do
    it 'has custom method for scraping certain feeds' do
      reset_scraper_for('Simple Malware List')
      subject.parse
      expect(subject).to be_empty
      expect(subject.reason).to eq 'No entries found'
    end
  end

  context '#parse_malware_corpus_tracker' do
    xit 'has custom method for scraping certain feeds' do
      reset_scraper_for('Malware Corpus Tracker')
      subject.parse
      expect(subject.reason).to be_nil
      expect(subject.entries.size).to be_positive
      expect(subject.entries).not_to include 'http://'
    end
  end

  context '#parse_bbcan177_malicious_ips' do
    it 'has custom method for scraping certain feeds' do
      reset_scraper_for('BBcan177 Malicious IPs')
      subject.parse
      expect(subject.reason).to be_nil
      expect(subject.entries.size).to be_positive
      expect_ip(subject.entries.first)
      expect(subject.entries).not_to(be_any { |i| i =~ %r{\Ahttps?://} })
    end
  end

  context '#parse_suspicious_dynamic_dns_providers' do
    it 'has custom method for scraping certain feeds' do
      reset_scraper_for('Suspicious Dynamic DNS Providers')
      subject.parse
      expect(subject.reason).to be_nil
      expect(subject.entries.size).to be_positive
      expect(subject.entries).to include('88.to')
      expect(subject.entries).not_to(be_any { |i| i.include?('#') })
    end
  end

  context '#parse_cridex_ips' do
    it 'has custom method for scraping certain feeds' do
      reset_scraper_for('Cridex IPs')
      subject.parse
      expect(subject.reason).to be_nil
      expect(subject.entries.size).to be_positive
      expect(subject.entries).to(be_all{|ip| expect_ip(ip)})
    end
  end
end
