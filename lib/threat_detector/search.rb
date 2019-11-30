# frozen_string_literal: true

module ThreatDetector
  # Search multiple entries in the threat database.
  #
  # While searching, we ensure that:
  # - URLs can be threat if their IP or host is a threat
  # - IPs is threat if present in CIDR networks which are a threat
  # - CIDR network is a threat if their wider CIDR network is a threat
  # - TODO: A host is a threat if the IP it resolves to is a threat
  # - TODO: An IP is a threat if the host it resolves to is a threat
  # - etc.
  #
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

    # Search provided queries in threat cache.
    # For each entry, we do a separate lookup in our cache.
    #
    def run(queries = [])
      queries = [@query] if queries.empty?

      queries.map do |query|
        self.query = query
        found = send "contains_#{@category}?"
        yield(query, found) if block_given?
        [query, found]
      end.to_h
    end

    # A URL is a threat if its included in the database,
    # or if its host/IP is included in the database.
    def contains_url?(needle = nil)
      @query = @query.gsub %r{\Ahttps?://}, ''
      return true if in_pool?(:url, needle)

      uri = URI.parse("http://#{@query}")
      contains_host?(uri.host) || contains_ip?(uri.host)
    end

    # A host is a threat if specifically present in database.
    def contains_host?(needle = nil)
      in_pool?(:host, needle)
    end

    # An IP is a threat if present in database, or if it belongs
    # to a network identified as threat.
    def contains_ip?(needle = nil)
      in_pool?(:ip, needle) || contained_in_network?(needle)
    end

    # A network is a threat if present in database, or if it belongs
    # to a wider network identified as threat.
    def contains_network?(needle = nil)
      in_pool?(:network, needle) || contained_in_network?(needle)
    end

    # Rarely, we get entries that can not be categorized and erreneous.
    # For these cases, lets mark them as found if directly searched for.
    def contains_unknown?(needle = nil)
      in_pool?(:unknown, needle)
    end

    protected

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
