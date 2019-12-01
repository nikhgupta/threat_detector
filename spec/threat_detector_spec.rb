# frozen_string_literal: true

RSpec.describe ThreatDetector do
  it 'has a version number' do
    expect(ThreatDetector::VERSION).not_to be nil
  end

  it 'provides a helper method to download feeds' do
    spy = spy()
    options = { ping: :pong }
    provided_block = ->(_) { puts 'block received' }
    expect(spy).to receive(:run) { |&block| expect(block).to be provided_block }
    expect(ThreatDetector::Downloader).to receive(:new).with(options).and_return spy

    described_class.download(options, &provided_block)
  end

  it 'provides a helper method to build cache fresh' do
    spy = spy()
    options = { ping: :pong }
    provided_block = ->(_) { puts 'block received' }
    expect(spy).to receive(:run) { |&block| expect(block).to be provided_block }
    expect(ThreatDetector::Cache).to receive(:new).with(options).and_return spy

    described_class.build_cache(options, &provided_block)
  end

  it 'provides a helper method to search terms in database' do
    spy = spy()
    options = { ping: :pong }
    keys = %w[term1 term2]
    provided_block = ->(_) { puts 'block received' }
    expect(spy).to receive(:run).with(keys) { |&block| expect(block).to be provided_block }
    expect(ThreatDetector::Search).to receive(:new).with(options).and_return spy

    described_class.search(keys, options, &provided_block)
  end
end
