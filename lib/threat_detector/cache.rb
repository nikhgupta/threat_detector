# frozen_string_literal: true

module ThreatDetector
  # Local cache for threats.
  #
  # Cache comprises of various subsets of data each targetting
  # a specific category, e.g. IP, Host, URL, etc.
  #
  # Separating our cache into various subsets allows for quicker searches,
  # e.g. for looking up IP, we can first check whether we have an IP match,
  # and later we can iterate through CIDR network entries for a match.
  #
  # We store data into Trie, and persist them on disk as Marshal data.
  # We can further improve upon the storage, but that has not been included,
  # at the moment.
  #
  class Cache
    include ThreatDetector::Utility

    # List of known subsets for cache
    SUBSETS = %i[ip host network url unknown].freeze

    # Each subset can be accessed directly in the cache
    # !@attribute [r] ip Subset for entries that are IPs
    # !@attribute [r] url Subset for entries that are URLs
    # !@attribute [r] host Subset for entries that are hosts
    # !@attribute [r] network Subset for entries of Network type
    # !@attribute [r] unknown Subset for entries that could not be categorized
    SUBSETS.each do |subset|
      attr_reader subset
    end

    # Utility method to readily load our cache with given options
    def self.load(options = {})
      new(options).load
    end

    attr_reader :options

    # Instantiate a new {ThreatDetector::Cache}
    #
    # @param  (see ThreatDetector::Utility#sanitize_options)
    # @option opts [String] :working_directory directory to download feeds and build cache in
    #
    # The default options are:
    #   working_directory: ~/.threat_detector
    def initialize(options = {})
      @options = sanitize_options(options)
      SUBSETS.each { |key| update_cache(key, get_cache(key)) }
    end

    # Build our cache from previously cached scraping data.
    # To update this data, we should use `ThreatDetector::Downloader`
    # class, which scrapes feed URLs from online sources and then,
    # run this method again.
    #
    # A block can be provided, e.g. for our CLI tool, to get details
    # about which file was updated in the cache and about the entries
    # that were updated. We use this block to print stats for
    # subsets in each file in our CLI tool.
    #
    # @yield [file, groupings] iterator for entries in each cached file
    # @yieldparam [String] file cached file path processed in current iteration
    # @yieldparam [Hash{Symbol => Array<String>}] groupings entries grouped by
    #   subset for each file
    # @return [Hash{Symbol => Integer}] hash with size of each subset
    # @see #finalize!
    # @see #add_entries
    def run
      scraped_feeds.each do |file|
        groupings = add_entries File.readlines(file).map(&:strip)
        yield(file, groupings) if block_given?
      end

      finalize!
    end

    # Group an array of enties based on the subset, and then, add it to the
    # corresponding subset in our cache.
    #
    # We add downcased entries to our cache, and for URLs - we
    # remove the trailing HTTP(s) schema.
    #
    # @return [Hash{Symbol => Array<String>}] groupings entries grouped by
    #   subset for each file
    #
    # @see #add_to_cache
    def add_entries(entries = [])
      group_by_subsets(entries).each do |subset, slice|
        cache = get_cache subset
        slice.each do |entry|
          add_to_cache subset, entry, cache
        end
        update_cache subset, cache
      end
    end

    # Helper method to quickly get a subset from our cache.
    #
    # @param [Symbol] subset subset to get cache for
    # @return [Rambling::Trie::Container]
    def get_cache(subset)
      instance_variable_get("@#{subset}") || Rambling::Trie.create
    end

    # Helper method to update a subset in our cache.
    #
    # @param [Symbol] subset subset to update cache for
    # @param [Rambling::Trie::Container] cache cache to update subset with
    # @return [Rambling::Trie::Container] cache instance passed in args
    def update_cache(subset, cache)
      instance_variable_set("@#{subset}", cache)
    end

    # Add an entry to a given subset
    #
    # @param [Symbol] subset subset to add entry to
    # @param [Rambling::Trie::Container] cache (optional) cache for subset
    # @param [String] entry entry to update subset with
    # @raise [ThreatDetector::Error] on invalid operations on Trie structure
    # @return [Rambling::Trie::Container] cache instance passed in args
    def add_to_cache(subset, entry, cache = nil)
      cache ||= get_cache(subset)
      entry = sanitized_entry_for_subset(entry, subset)
      cache << entry unless entry.strip.empty?
      cache
    rescue Rambling::Trie::InvalidOperation => e
      raise_error e.message
    end

    # Load various subsets in our cache.
    #
    # @return [self] cache instance after loading subsets
    def load
      SUBSETS.each do |key|
        path = save_path_for(key)
        next unless File.exist?(path)

        update_cache key, Rambling::Trie.load(path)
      end

      self
    end

    # For each subset in our cache, persist it to disk.
    #
    # @return [Hash{Symbol => Integer}] hash with size of each subset
    def finalize!
      SUBSETS.map do |key|
        cache = get_cache(key)
        next unless cache

        Rambling::Trie.dump(cache.compress, save_path_for(key))
        [key, cache.size]
      end.to_h
    end

    private

    # Sanitize an entry just before it is fed to a subset.
    # This can be used to avoid unnecessary queries when searching, later.
    #
    # @api private
    # @return [String] sanitized entry for given subset
    def sanitized_entry_for_subset(entry, subset)
      case subset
      when :url
        entry.downcase.gsub(%r{\Ahttps?://}, '').chomp('/')
      else
        entry.downcase
      end
    end

    # Find all scraped feeds already downloaded
    # @api private
    # @return [Array] array of file paths for scraped feeds
    def scraped_feeds
      Dir.glob(File.join(working_directory, 'feeds', '*.txt'))
    end

    # Path to the cache file for a given subset.
    # @api private
    # @return [String]
    def save_path_for(subset)
      File.join(working_directory, "#{subset}.marshal")
    end

    # Group entries based on which subset it belongs to.
    # @api private
    # @return [Hash{Symbol => Array<String>}] entries grouped by subsets
    def group_by_subsets(entries)
      entries.group_by do |entry|
        categorize_ip_or_uri(entry)
      end
    end
  end
end
