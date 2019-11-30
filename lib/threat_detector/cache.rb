# frozen_string_literal: true

module ThreatDetector
  # Local cache for threats.
  #
  # Cache comprises of various subsets/pools of data each targetting
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
    POOLS = %i[ip host network url unknown].freeze

    # Each subset can be accessed directly in the cache
    POOLS.each do |pool|
      attr_reader pool
    end

    # Utility method to readily load our cache with given options
    def self.load(options = {})
      new(options).load
    end

    # Instantiate our cache.
    # 
    # We try to load trie nodes for each subset in our cache.
    # Having subsets allows for much faster searches, as we
    # can utilize other inferences from our search.
    #
    def initialize(options = {})
      @options = sanitize_options(options)
      POOLS.each { |key| update_cache(key, nil) }
    end

    # Build our cache from previously cached scraping data.
    # To update this data, we should use `ThreatDetector::Downloader`
    # class, which scrapes available ThreatFeeds.io feed URLs.
    #
    # A block can be provided, e.g. for our CLI tool, to get details
    # about which file was updated in the cache and about the entries
    # that were updated. We use this block to print stats for
    # subsets in each file.
    #
    def run
      cached_files.each do |file|
        subsets = add_entries File.readlines(file).map(&:strip)
        yield(file, subsets) if block_given?
      end

      finalize!
    end

    # Group an array based on the subset, and then, add it to the
    # corresponding subset in our cache.
    # 
    # We add downcased entries to our cache, and for URLs - we
    # remove the trailing HTTP(s) schema.
    #
    def add_entries(entries = [])
      group_by_subsets(entries).each do |pool, slice|
        cache = get_cache pool
        slice.each do |entry|
          entry = sanitized_entry_for_pool(entry, pool)
          cache << entry unless entry.strip.empty?
        end
        update_cache pool, cache
      end
    end

    # Helper method to quickly get a subset from our cache
    def get_cache(pool)
      instance_variable_get("@#{pool}") || Rambling::Trie.create
    end

    # Helper method to update a subset in our cache
    def update_cache(pool, cache)
      instance_variable_set("@#{pool}", cache)
    end

    # Load various subsets in our cache.
    def load
      POOLS.each do |key|
        path = save_path_for(key)
        next unless File.exist?(path)

        update_cache key, Rambling::Trie.load(path)
      end

      self
    end

    # For each subset in our cache, compress the available data
    # to reduce size and then, persist to disk.
    #
    # Please, note that, using `compress!` makes the subset
    # unavailable for further addition of threats, and will
    # result in error, i.e. our subsets are unmutable afterwards.
    #
    def finalize!
      POOLS.map do |key|
        cache = get_cache(key)
        next unless cache

        Rambling::Trie.dump(cache.compress!, save_path_for(key))
        [key, cache.size]
      end.to_h
    end

    # Sanitize an entry just before it is fed to a subset.
    # 
    # This can be used to avoid unnecessary queries when searching, later.
    #
    def sanitized_entry_for_pool(entry, pool)
      case pool
      when :url
        entry.downcase.gsub %r{\Ahttps?://}, ''
      else
        entry.downcase
      end
    end

    protected

    def cached_files
      Dir.glob(File.join(@options[:working_directory], 'feeds', '*.txt'))
    end

    def save_path_for(name)
      File.join(@options[:working_directory], "#{name}.marshal")
    end

    def group_by_subsets(entries)
      entries.group_by do |entry|
        categorize_ip_or_uri(entry)
      end
    end
  end
end
