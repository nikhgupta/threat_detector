# frozen_string_literal: true

RSpec.describe ThreatDetector::Downloader do
  let(:valid_feed) { 'IPSpamList' }
  let(:invalid_feed) { 'Malware URLs' }
  let(:work_dir) { File.join(ThreatDetector::ROOT, 'tmp') }
  subject { described_class.new(working_directory: work_dir, refresh: true) }

  it 'defaults to directory inside user home for working directory' do
    downloader = described_class.new
    work_dir = downloader.working_directory
    expect(work_dir).to eq File.join(ENV['HOME'], '.threat_detector')
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'allows specifying a custom working directory' do
    work_dir = subject.working_directory
    expect(work_dir).to eq work_dir
    expect(File.directory?(work_dir)).to be_truthy
  end

  context '#fetch_feeds', :vcr do
    it 'fetches feeds data from online sources' do
      feeds = subject.fetch_feeds
      expect(feeds.length).to be_positive
      expect(feeds).to include(hash_including('name' => valid_feed))
      expect(feeds).not_to include(hash_including('name' => invalid_feed))
    end

    it 'raises errors when feeds data can not be obtained' do
      stub_const('ThreatDetector::Downloader::SOURCES',
                 threatfeeds: 'http://nonexistant.com')

      error = 'Could not find feeds JSON for ThreatFeeds.io'
      expect do
        subject.fetch_feeds
      end.to raise_error(ThreatDetector::Error, error)
    end
  end

  context '#run', :vcr do
    it 'delegates to fetch feeds from online sources' do
      expect(subject).to receive(:fetch_feeds).and_return []

      subject.run
    end

    it 'scrapes threat entries from each feed' do
      scraper = stub_scraper_and_feeds_for(subject)
      expect(scraper).to receive(:for).once.and_call_original

      counter = 0
      feeds = subject.run { |_, sc| counter += sc.entries.size }

      expect(counter).to eq 50
      expect(feeds.size).to eq 1
      expect(feeds).to include(
        'url' => instance_of(String),
        'source' => 'threatfeeds',
        'name' => valid_feed
      )
    end

    it 'yields name, url and scraper for each feed' do
      scraper = stub_scraper_and_feeds_for(subject)
      expect(scraper).to receive(:for).twice.and_call_original

      expect do |b|
        subject.run(&b)
      end.to yield_with_args(hash_including('name' => valid_feed), scraper)

      expect do |b|
        subject.run(&b)
      end.not_to yield_with_args(hash_including('name' => invalid_feed), scraper)
    end

    it 'saves content for the feeds on disk' do
      stub_scraper_and_feeds_for(subject)

      feeds_path = nil
      subject.run do |_item, scraper|
        feeds_path = scraper.save_path
      end
      expect(feeds_path).to include(subject.working_directory)
      expect(File.readable?(feeds_path)).to be_truthy
    end
  end
end
