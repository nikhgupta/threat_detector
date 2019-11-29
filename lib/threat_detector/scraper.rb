# frozen_string_literal: true

module ThreatDetector
  class Scraper
    extend Enumerable
    extend Forwardable
    include ThreatDetector::Utility

    attr_reader :name, :url, :path, :reason, :entries
    def_delegators :entries, :each, :take, :map, :size, :<<, :shuffle, :empty?

    def initialize(name, options = {})
      @options = sanitize_options(options)
      self.name = name
    end

    def name=(name)
      @name = name
      @entries = []

      @config = @options[:feeds_config_path]
      @config = File.exist?(@config) ? YAML.load_file(@config) : {}
      @config = @config[name]
    end

    def url=(url)
      @url = url.strip
      @path = save_path
      @page = @reason = nil
      @entries = []
    end

    def parse
      return add_reason('Found cached entries') if cached?

      fetch_page url
      return add_reason('Invalid page response') unless valid_page?

      method = @config['custom'] ? "parse_#{name}" : :fetch_entries
      @entries = send(method)

      add_reason 'No entries found' if empty?
    rescue Curl::Err::MalformedURLError
      add_reason 'Maltformed URL passed'
    rescue Curl::Err::TimeoutError
      add_reason 'Timeout received'
    end

    def save_entries
      return if empty?

      File.open(save_path, 'w') { |f| f.puts @entries }
    end

    def parse_and_save_entries
      parse
      save_entries
      block_given? ? yield(entries) : entries
    end

    def save_path
      path = File.join(@options[:dir], 'feeds')
      FileUtils.mkdir_p(path) unless File.directory?(path)

      hash = Digest::MD5.hexdigest(@url)
      File.join(path, "#{name}-#{hash[0..8]}.txt")
    end

    def add_reason(message)
      @reason ||= message
    end

    def cached?
      !@options[:refresh] && File.exist?(save_path)
    end

    protected

    def parse_simple_malware_list
      []
    end

    def parse_bbcan177_malicious_ips
      fetch_entries.reject { |en| en =~ %r{\Ahttps://} }
    end

    def parse_suspicious_dynamic_dns_providers
      fetch_entries.map { |en| en.split(/(\s+|\#)/).first }
    end

    def parse_cridex_ips
      purl = @page.url
      csv_links(@page).map do |url|
        next if File.basename(url) == 'malware_hashes.csv'

        fetch_entries_via URI.parse(purl).merge(URI.parse(url)).to_s
      end.compact.flatten.uniq
    end
    alias parse_feodo_tracker parse_cridex_ips

    def parse_malware_corpus_tracker
      fetch_entries.reject { |en| en == 'http://' }
    end

    private

    def fetch_entries_via(url = nil)
      fetch_page url if url
      rows = @page.body_str.split("\n").map do |line|
        process_row(line, @config.fetch('column', 0))
      end.compact

      rows.shift if @config.fetch('header', false)
      rows.reject(&:empty?)
    end
    alias fetch_entries fetch_entries_via

    def process_row(row, col)
      return if row.strip[0] == @config.fetch('ignore_starting_with', '#')

      row = row.split(@config.fetch('delimiter', ','), col + 2)
      return if row.empty?

      row = row[col].gsub(/\s+\#.*\z/, '').strip
      @config.fetch('quoted', false) ? row.gsub(/\"(.*)\"/, '\1') : row
    end

    def valid_page?
      return false unless @page
      return false if @page.response_code >= 400

      @page.body_str.strip.length.positive?
    end

    def csv_links(page)
      html = Nokogiri::HTML(page.body_str)
      urls = html.search('a').map { |a| a.attr('href') }
      urls.select { |a| File.extname(a) == '.csv' }
    end
  end
end