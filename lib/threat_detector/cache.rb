# frozen_string_literal: true

module ThreatDetector
  class Cache
    include ThreatDetector::Utility

    POOLS = %i[ip host network url unknown].freeze

    POOLS.each do |pool|
      attr_reader pool
    end

    def self.load(options = {})
      new(options).load
    end

    def initialize(options = {})
      @options = sanitize_options(options)
      POOLS.each { |key| update_cache(key, nil) }
    end

    def run
      cached_files.each do |file|
        grouped = add_entries File.readlines(file).map(&:strip)
        yield(file, grouped) if block_given?
      end

      finalize!
    end

    def add_entries(entries = [])
      group_by_classification(entries).each do |pool, slice|
        cache = get_cache pool
        slice.each do |entry|
          entry = sanitized_entry_for_pool(entry, pool)
          cache << entry unless entry.strip.empty?
        end
        update_cache pool, cache
      end
    end

    def get_cache(pool)
      instance_variable_get("@#{pool}") || Rambling::Trie.create
    end

    def update_cache(pool, cache)
      instance_variable_set("@#{pool}", cache)
    end

    def load
      POOLS.each do |key|
        path = save_path_for(key)
        next unless File.exist?(path)

        update_cache key, Rambling::Trie.load(path)
      end

      self
    end

    def finalize!
      POOLS.map do |key|
        cache = get_cache(key)
        next unless cache

        Rambling::Trie.dump(cache.compress!, save_path_for(key))
        [key, cache.size]
      end.to_h
    end

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

    def group_by_classification(entries)
      entries.group_by do |entry|
        categorize_ip_or_uri(entry)
      end
    end
  end
end
