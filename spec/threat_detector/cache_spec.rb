# frozen_string_literal: true

RSpec.describe ThreatDetector::Cache do
  let(:work_dir) { File.join(ThreatDetector::ROOT, 'tmp') }
  subject { described_class.new(working_directory: work_dir) }
  let(:cache_entries) do
    <<-ENTRIES.split("\n") # .map(&:strip)
      115.113.203.147
      51.15.70.121
      62.210.188.15
      88.to
      92.244.36.64/28
      http://124.129.34.212:2000/2897
      http://159.89.34.175/bins/sora.arm7
      http://alcheewale.com/minsee/ragaba.php?l=walala8.cab
      http://jscomputadores.com/site/whatsapp/
      http://scalyze.com/IRS-Letters-062018-026/28/
      minero.cc
      http://k99915xt.beget.tech/
      unsafe-string
    ENTRIES
  end

  def stub_scraped_feeds
    file_path = double
    allow(subject).to receive(:scraped_feeds).and_return [file_path]
    allow(File).to receive(:readlines).with(file_path).and_return cache_entries
    file_path
  end

  it 'provides a helper method to quickly load the cache' do
    ins = double
    options = { ping: :pong }
    expect(described_class).to receive(:new).with(options).and_return ins
    expect(ins).to receive(:load).with(no_args)

    described_class.load(options)
  end

  it 'defaults to directory inside user home for working directory' do
    work_dir = described_class.new.working_directory
    expect(work_dir).to eq File.join(ENV['HOME'], '.threat_detector')
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'allows specifying a custom working directory' do
    work_dir = subject.working_directory
    expect(work_dir).to eq work_dir
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'has a list of subsets defined for each category possible for threat entries' do
    subsets = ThreatDetector::Cache::SUBSETS
    expect(subsets.length).to eq 5
    expect(subsets).to include(:ip, :url, :host, :network, :unknown)
  end

  it 'provides direct access to a defined subset' do
    stub_scraped_feeds
    subject.load

    expect(subject.ip).to be_a(Rambling::Trie::Container)
    expect(subject.url).to be_a(Rambling::Trie::Container)
    expect(subject.host).to be_a(Rambling::Trie::Container)
    expect(subject.network).to be_a(Rambling::Trie::Container)
    expect(subject.unknown).to be_a(Rambling::Trie::Container)
    expect(subject).not_to respond_to(:random_subnet)
  end

  context '#run' do
    it 'yields a list of files with existing scraped feeds data' do
      path = stub_scraped_feeds
      expect do |b|
        subject.run(&b)
      end.to yield_with_args(
        path,
        a_hash_including(host: a_collection_including('88.to'))
      )
    end

    it 'saves cache subsets to disk after adding threat entries' do
      expect(subject.host).to be_a Rambling::Trie::Container

      expect(subject.host).not_to include '88.to'
      expect(subject.ip).not_to include '115.113.203.147'
      expect(subject.network).not_to include '92.244.36.64/28'
      expect(subject.url).not_to include 'http://124.129.34.212:2000/2897'

      stub_scraped_feeds
      subject.run
      expect(subject.host).to include '88.to'
      expect(subject.ip).to include '115.113.203.147'
      expect(subject.network).to include '92.244.36.64/28'
      expect(subject.url).to include '124.129.34.212:2000/2897'
      expect(subject.url).to include 'scalyze.com/irs-letters-062018-026/28'
    end

    it 'normalizes URLs before saving them to cache' do
      stub_scraped_feeds
      subject.run

      expect(subject.url).to include 'scalyze.com/irs-letters-062018-026/28'
      expect(subject.url).not_to include 'scalyze.com/IRS-Letters-062018-026/28'
      expect(subject.url).not_to include 'scalyze.com/IRS-Letters-062018-026/28/'
      expect(subject.url).not_to include 'http://scalyze.com/IRS-Letters-062018-026/28'
    end
  end

  it 'raises an error when cache restricts operations for some reason' do
    stub_scraped_feeds
    subject.run

    subject.host.compress!
    expect do
      subject.add_to_cache :host, 'nikhgupta.com'
    end.to raise_error(ThreatDetector::Error, 'Cannot add word to compressed trie')
  end
end
