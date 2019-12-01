# frozen_string_literal: true

module ThreatDetector
  # Scrape a given feed URL from ThreatFeeds.io
  #
  # This class generalizes to all feed URLs. Often times, custom settings are
  # required for some feeds, which can be provided as a YAML config file. Each
  # section in this file pertains to a scraper (identified by its name).
  #
  class Scraper
    include ThreatDetector::Utility

    # Extend class to make it enumerable. We provide `each` method below.
    extend Enumerable

    # Delegate array-like methods to our entries to make them behave like array
    extend Forwardable
    def_delegators :@entries, :each, :take, :map, :size, :<<, :shuffle, :empty?

    attr_reader :name, :url, :reason, :options, :entries, :config

    # Instantiate a new {ThreatDetector::Scraper}
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
      reset!
    end

    # Set the name for this scraper. This, also, resets the scraping config, as well as,
    # other internal states for this scraper. This name is used to fetch appropriate config
    # settings.
    # !@attribute [w] name name for this scraper
    def name=(name)
      @name = name.to_s.parameterize.underscore
      reset!
    end

    # Set the url for this scraper. This, also, resets the scraping config, as well as,
    # other internal states for this scraper. Scraper with same name can have multiple
    # URLs which may have different threat entries.
    # !@attribute [w] url url for this scraper
    def url=(url)
      @url = url.to_s.strip
      reset!
    end

    # Reset the scraper instance to work for a feed with provided name and URL.
    # Though, this method returns the resetted scraper instance for chaining purposes.
    # @param [String] name name for this scraper
    # @param [String, URI] url url for this scraper
    # @return [self] resetted scraper instance with name and URL for feed configured
    def for(name, url)
      self.url = url
      self.name = name
      self
    end

    # Check if the scraper is configured via YAML scraping configuration?
    # @return [Bool]
    def configured?
      !@config.empty?
    end

    # Check whether the cached file exists? Also, check if we are not refreshing the feeds?
    # @return [Bool]
    def cached?
      !refresh? && File.exist?(save_path)
    end

    # Add a reason to the current scraper instance for skipping a feed.
    # @return [self]
    def add_reason(message)
      @reason ||= message
      self
    end

    # Method that scrapes and parses the page for a feed with given name and URL
    #
    # We use a generalized method {#fetch_entries_via} for most feeds, and
    # resort to custom methods defined in this class for scraping some feeds.
    #
    # Every time that we ignore/skip a feed for some reason, we update the
    # scraper instance to contain the reason for skipping that feed.
    #
    # @note If a feed has alreayd been downloaded locally, it will be skipped.
    #   If you want to fetch such a feed again, you need to set `refresh`
    #   attribute to `true`.
    #
    # @return [self] scraper instance with reason for skipping and/or entries
    #   after scraping was performed
    def parse
      return add_reason('Found cached entries') if cached?

      fetch_page url
      return add_reason('Invalid page response') unless valid_page?

      method = @config['custom'] ? "parse_#{name}" : :fetch_entries
      @entries = send(method)

      empty? ? add_reason('No entries found') : self
    rescue Curl::Err::MalformedURLError
      add_reason 'Malformed URL passed'
    rescue Curl::Err::TimeoutError
      add_reason 'Timeout received'
    end

    # Save entries to local cache files.
    # These files are different than the Trie based dumps, and are useful
    # to quickly update/sync our data from online sources
    #
    # @note No entries will be saved if the name or URL is not set.
    # @return [String,nil] path to the file where entries were saved
    def save_entries
      return if empty?

      File.open(save_path, 'w') { |f| f.puts @entries }
      save_path
    end

    # Utility method to scrape and save entries so obtained.
    #
    # @yield [entries] hook to work with entries after scraping current feed
    # @yieldparam [Array<String>] entries scraper entries fetched from the current feed
    # @return [self]
    def parse_and_save_entries
      parse
      save_entries
      yield(entries) if block_given?
      entries
    end

    # Path to file where entries from current feed will be saved.
    # Since, there can be multiple feeds with the same name, the save path for
    # a feed is appended with a MD5 hash substring.
    # @return [String,nil] Path for the file or nil if name or URL is not set
    def save_path
      return unless name && url

      path = File.join(working_directory, 'feeds')
      FileUtils.mkdir_p(path) unless File.directory?(path)

      hash = Digest::MD5.hexdigest(url)
      File.join(path, "#{name}-#{hash[0..8]}.txt")
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

    # Reset the internal state of the scraper.
    def reset!
      @entries = []
      @page = @reason = nil

      @config = @options[:feeds_config_path]
      @config = File.exist?(@config) ? YAML.load_file(@config) : {}
      @config = @config.key?(name) ? @config[name] : {}

      self
    end

    # Fetch entries by scraping the Feed URL.
    #
    # We sanitize the feed to read a specific column. This method
    # generalizes to most feed URLs to obtain threat entries.
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

    # Check whether we have a valid page based on response code and content.
    def valid_page?
      return false unless @page
      return false if @page.response_code >= 400

      @page.body_str.strip.length.positive?
    end

    # Fetch csv links from a given page
    def csv_links(page)
      html = Nokogiri::HTML(page.body_str)
      urls = html.search('a').map { |a| a.attr('href') }
      urls.select { |a| File.extname(a) == '.csv' }
    end
  end
end
