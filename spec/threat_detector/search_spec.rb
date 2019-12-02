# frozen_string_literal: true

RSpec.describe ThreatDetector::Search do
  let(:work_dir) { File.join(ThreatDetector::ROOT, 'tmp') }
  subject { described_class.new(working_directory: work_dir) }
  let(:threat_entries) do
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

  def verify_unsafe(entry, options = {})
    reason = options.delete(:reason)
    options[:resolve] = options.fetch(:resolve, false)
    data = subject.find(entry, options).merge(search: entry)
    expect(data).to include(safe: false)
    expect(data).to include(reason: reason) if reason
  end

  def verify_safe(entry, options = {})
    options[:resolve] = options.fetch(:resolve, false)
    data = subject.find(entry, options).merge(search: entry)
    expect(data).to include(safe: true)
  end

  def stub_cache
    file_path = double
    cache = ThreatDetector::Cache.new(subject.options)
    allow(cache).to receive(:scraped_feeds).and_return [file_path]
    allow(File).to receive(:readlines).with(file_path).and_return threat_entries
    allow(ThreatDetector::Cache).to receive(:load).and_return cache
  end

  it 'defaults to directory inside user home for working directory' do
    stub_cache
    work_dir = described_class.new.working_directory
    expect(work_dir).to eq File.join(ENV['HOME'], '.threat_detector')
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'allows specifying a custom working directory' do
    work_dir = subject.working_directory
    expect(work_dir).to eq work_dir
    expect(File.directory?(work_dir)).to be_truthy
  end

  it 'loads the threat cache when initialized' do
    expect(subject.cache).to be_a ThreatDetector::Cache
    expect(subject.cache.ip).to be_a Rambling::Trie::Container
    expect(subject.cache.host).to include '88.to'
    expect(subject.cache.host).not_to include 'skylab.n-engine.com' # not in stubbed cache
  end

  context '#find' do
    it 'provides reason and identified entry when marking a threat as unsafe' do
      expect(subject.find('88.safe')).to eq(safe: true, type: :host)
      expect(subject.find('88.to')).to eq(
        safe: false, reason: :host,
        type: :host, identified: '88.to'
      )
    end

    it 'marks IP as unsafe when found in database, directly' do
      verify_safe '159.89.34.175'
      verify_safe '124.129.34.212'
      verify_unsafe '115.113.203.147'
      verify_unsafe '62.210.188.15', reason: :ip
    end

    it 'marks IP as unsafe when found in unsafe network' do
      verify_safe '92.244.36.62'
      verify_safe '92.244.36.80'
      verify_unsafe '92.244.36.70', reason: :ip_in_network
      verify_unsafe '92.244.36.79', reason: :ip_in_network
    end

    it 'marks IP directly when smarter searching is turned off' do
      verify_safe '92.244.36.70', smarter: false
      verify_safe '92.244.36.79', smarter: false
    end

    it 'marks host as unsafe when found in database, directly' do
      verify_safe 'minero.ccno'
      verify_safe 'scalyze.com'
      verify_safe 'k99915xt.beget.tech'
      verify_unsafe 'minero.cc'
    end

    it 'marks networks as unsafe when found in database, directly' do
      verify_safe '92.244.36.60/28'
      verify_safe '92.244.32.64/28'
      verify_unsafe '92.244.36.64/28'
    end

    it 'marks networks as unsafe when found in wider unsafe network' do
      verify_unsafe '92.244.36.64/29', reason: :in_wider_network
      verify_unsafe '92.244.36.64/30', reason: :in_wider_network
      verify_unsafe '92.244.36.64/31', reason: :in_wider_network
      verify_unsafe '92.244.36.64/32', reason: :in_wider_network
      verify_unsafe '92.244.36.70/30', reason: :in_wider_network

      verify_safe '92.244.36.60/24'
      verify_safe '92.244.36.60/28'
      verify_safe '92.244.36.64/26'
    end

    it 'marks networks directly when smarter searching is turned off' do
      verify_safe '92.244.36.64/29', smarter: false
      verify_safe '92.244.36.64/30', smarter: false
      verify_safe '92.244.36.64/31', smarter: false
      verify_safe '92.244.36.64/32', smarter: false
      verify_safe '92.244.36.70/30', smarter: false
      verify_safe '92.244.36.60/24', smarter: false
      verify_safe '92.244.36.60/28', smarter: false

      verify_unsafe '92.244.36.64/28', smarter: false, reason: :network
    end

    it 'marks URL as unsafe when found in database, directly' do
      verify_unsafe '124.129.34.212:2000/2897', reason: :url
      verify_unsafe 'http://124.129.34.212:2000/2897'
      verify_unsafe 'http://124.129.34.212:2000/2897/'
      verify_unsafe 'scalyze.com/irs-letters-062018-026/28'
      verify_unsafe 'scalyze.com/IRS-Letters-062018-026/28/'
      verify_unsafe 'http://scalyze.com/irs-Letters-062018-026/28/'

      verify_safe 'http://scalyze.com/'
      verify_safe 'http://124.129.34.212:2000/'
      verify_safe 'unsafe-string.com/test-page'
      verify_safe 'http://scalyze.com/IRS-Letters-062018-026/'
    end

    it 'marks URL as unsafe when host/IP is a threat' do
      verify_unsafe 'https://minero.cc', reason: :host
      verify_unsafe 'miNEro.CC/test-page', reason: :host
      verify_unsafe 'https://62.210.188.15', reason: :ip
      verify_unsafe 'http://88.TO/TEST-page/', reason: :host
      verify_unsafe 'http://minero.cc/test-page', reason: :host
      verify_unsafe 'http://k99915xt.BEGET.tech/', reason: :host
      verify_unsafe 'http://62.210.188.15/test-page', reason: :ip
      verify_unsafe 'https://92.244.36.79/test-page', reason: :ip_in_network
      verify_safe 'http://scalyze.com/test-page'
      verify_safe 'https://92.244.36.80/test-page'
      verify_safe 'http://k99915xt.beget.tech/test-page'
    end

    it 'marks URLs directly when smarter searching is turned off' do
      verify_safe 'http://minero.cc', smarter: false
      verify_safe 'miNEro.CC/test-page', smarter: false
      verify_safe 'http://88.TO/TEST-page/', smarter: false
      verify_safe 'http://minero.cc/test-page', smarter: false
      verify_safe 'http://scalyze.com/test-page', smarter: false
      verify_safe 'http://62.210.188.15/test-page', smarter: false
      verify_safe 'https://92.244.36.79/test-page', smarter: false
      verify_unsafe 'scalyze.com/IRS-Letters-062018-026/28/', reason: :url
    end

    it 'marks random strings if found directly in database' do
      verify_safe ''
      verify_safe ' '
      verify_safe '\n'
      verify_safe 'random-string'
      verify_unsafe 'unsafe-string', reason: :matched
    end
  end

  context '#process_items' do
    it 'yields search term and results' do
      expect do |b|
        subject.process_items('https://88.to/test-page', &b)
      end.to yield_with_args(
        'https://88.to/test-page',
        safe: false, identified: '88.to', type: :url, reason: :host
      )
    end

    it 'saves items to file with given path' do
      path = File.join(subject.working_directory, 'results.txt')
      entries = subject.process_items(
        'https://88.to/test-page', '92.244.36.64/29', 'test.com', save: path)

      contents = File.readlines(path).map(&:strip)
      expect(contents).to include 'https://88.to/test-page,url,false,host,88.to'
      expect(contents).to include '92.244.36.64/29,network,false,in_network,92.244.36.64/28'
      expect(contents).to include 'test.com,host,true,,'

      expect(entries['https://88.to/test-page'][:identified]).to eq '88.to'
      expect(entries.size).to eq 3
    end

    it 'turns off smarter searching via options' do
      entries = subject.process_items(
        'https://88.to/test-page', '92.244.36.64/29', '88.to', smarter: false)

      expect(entries['https://88.to/test-page'][:safe]).to be_truthy
      expect(entries['92.244.36.64/29'][:safe]).to be_truthy
      expect(entries['88.to'][:safe]).to be_falsey
    end
  end

  context '#process' do
    it 'yields search term and results' do
      expect do |b|
        subject.process('https://88.to/test-page', &b)
      end.to yield_with_args(
        'https://88.to/test-page',
        safe: false, identified: '88.to', type: :url, reason: :host
      )
    end

    it 'allows searching for terms directly as well as by supplying file paths' do
      file = double
      contents = "test.com \nminero.cc\n".split("\n")
      expect(File).to receive(:exist?).with(file).and_return true
      expect(File).to receive(:exist?).with(any_args).at_least(1).and_call_original
      expect(File).to receive(:readable?).with(file).and_return true
      expect(File).to receive(:readlines).with(file).and_return contents

      entries = subject.process(file, '88.to', '88.to/test', smarter: false)
      expect(entries.size).to eq 4
      expect(entries['88.to']).to include(safe: false)
      expect(entries['88.to/test']).to include(safe: true)
      expect(entries['minero.cc']).to include(safe: false)
      expect(entries['test.com']).to include(safe: true)
    end

    it 'raises an error when file provided is unreadable but exists' do
      file = double(to_str: '/some/path', to_s: '/some/path')
      expect(File).to receive(:exist?).at_least(1).and_return true
      expect(File).to receive(:readable?).with(file).and_return false

      expect do
        subject.process(file, '88.to', '88.to/test', smarter: false)
      end.to raise_error(ThreatDetector::Error, 'Found unreadable item file: /some/path')
    end
  end
end
