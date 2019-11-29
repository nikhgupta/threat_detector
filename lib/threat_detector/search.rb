# frozen_string_literal: true

module ThreatDetector
  class Search
    include ThreatDetector::Utility
    attr_reader :query, :category

    def initialize(options = {})
      @options = sanitize_options(options)
      @cache = ThreatDetector::Cache.load(@options)
    end

    def query=(query)
      @query = query.downcase
      @category = categorize_ip_or_uri(@query)
    end

    def run(queries = [])
      queries = [@query] if queries.empty?

      queries.map do |query|
        self.query = query
        found = send "contains_#{@category}?"
        yield(query, found) if block_given?
        [query, found]
      end.to_h
    end

    def contains_url?(needle = nil)
      @query = @query.gsub %r{\Ahttps?://}, ''
      return true if in_pool?(:url, needle)

      uri = URI.parse("http://#{@query}")
      contains_host?(uri.host) || contains_ip?(uri.host)
    end

    def contains_host?(needle = nil)
      in_pool?(:host, needle)
    end

    def contains_ip?(needle = nil)
      in_pool?(:ip, needle) || contained_in_network?(needle)
    end

    def contains_network?(needle = nil)
      in_pool?(:network, needle) || contained_in_network?(needle)
    end

    def contains_unknown?(needle = nil)
      in_pool?(:unknown, needle)
    end

    def in_pool?(key, needle = nil)
      needle ||= @query
      @cache.send(key).include?(needle)
    end

    def contained_in_network?(needle = nil)
      needle ||= @query
      ip = IPAddress.parse(needle)
      @cache.network.any? { |net| IPAddress.parse(net).include?(ip) }
    rescue ArgumentError
      false
    end
  end
end
