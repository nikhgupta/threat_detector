# frozen_string_literal: true

module ThreatDetector
  # Class used to search threats in our {ThreatDetector::Cache}
  #
  # ThreatDetector tries to be smart in understanding that the database may not
  # necessarily contain the exact search item, and often, employs logic in
  # deciding whether a given IP, network, host or URL is a threat. For example,
  # in addition to directly matching threats in this database, it knows that:
  #
  # - An IP is a threat if it belongs to an identified network.
  # - A network is a threat if it belongs to a wider identified network.
  # - An IP is a threat if the hostname it resolves to is marked as a threat.
  # - A host can be a threat if the IP it resolves to is marked as a threat.
  # - A url can be a threat if its hostname or IP is marked as a threat.
  # - etc.
  #
  # @note This loads our threat cache to memory, and therefore, we should
  #   re-use this instance, where possible.
  class Search
    include ThreatDetector::Utility

    attr_reader :cache, :options

    # Instantiate a new {ThreatDetector::Search}
    #
    # @note This loads our threat cache to memory, and therefore, we should
    #   re-use this instance, where possible.
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
      @cache = ThreatDetector::Cache.load(@options)
    end

    # Search for the given item in threats database.
    #
    # @param [String, URI, #to_s] item Item to search in database
    # @param [Hash] options search options for this search
    # @option options [Bool] :smarter Apply heuristics to identify threat smartly?
    # @option options [Bool] :resolve Whether to resolve IP/hosts to host/IPs for identifying threats?
    # @return [Hash] hash containing keys that correspond to:
    #   - :safe - whether item was identified as safe or not
    #   - :type - category for this item from IP, URL, Host, Network or Unknown
    #   - :reason - if unsafe, the reason why this item was marked as unsafe
    #   - :identified - relevant threat item found in the database
    #
    # By default, options are:
    #
    #     smarter: true, resolve: true
    #
    # Passing `smarter: false` will turn off:
    # - An IP is a threat if it belongs to an identified network.
    # - A network is a threat if it belongs to a wider identified network.
    # - A url can be a threat if its hostname or IP is marked as a threat.
    #
    # Passing `resolve: false` will turn off:
    # - A host can be a threat if the IP it resolves to is marked as a threat.
    # - An IP is a threat if the hostname it resolves to is marked as a threat.
    def find(item, options = {})
      return { safe: true, type: :unknown } if item.to_s.strip.empty?

      category = categorize_ip_or_uri(item)
      reason, found = send "unsafe_#{category}?", item, options
      data = options.merge(safe: !found, type: category)
      return data unless found

      data.merge(reason: reason, identified: found)
    end

    # Search multiple given items in the database.
    # Optionally, append the results of this search in a CSV file.
    #
    # @overload process_items(*keys, options = {}, &block)
    #   @param [Array<String, URI, #to_s>] - search items
    #   @param [Hash] options search options for this search
    #   @option options [Bool] :smarter use heuristics to check threats smartly?
    #   @option options [Bool] :resolve Whether to resolve IP/hosts to host/IPs
    #     for identifying threats?
    #   @option options [String] :save (optional) Path to CSV file where search
    #     results will be appended
    #   @yield [item, data] iterator for search results
    #   @yieldparam [String] item current search item
    #   @yieldparam [Hash] data search results for current search item
    #   @return [Array<Hash>] array of search results
    #
    # @see #find
    def process_items(*args, &block)
      items, options = extract_options(args)

      results = items.map do |item|
        data = find(item, options.except(:save))
        block.call(item, data) if block
        [item, data]
      end.to_h

      options[:save] ? append_to_csv(results, options[:save]) : results
    end

    # Identify multiple items or files against threat database.
    # Optionally, append the results of this search in a CSV file.
    #
    # If for a given search term, a file exists on disk with the same name, and
    # is readable, then, preference will be given to that file. If you are only
    # specifying search terms, please use {#process_items} instead.
    #
    # @overload process(*keys, options = {}, &block)
    #   @param [Array<String, URI, File, #to_s, #read>] - search items or files
    #     containing search items
    #   @param [Hash] options search options for this search
    #   @option options [Bool] :smarter use heuristics to check threat smartly?
    #   @option options [Bool] :resolve Whether to resolve IP/hosts to host/IPs
    #     for identifying threats?
    #   @option options [String] :save (optional) Path to CSV file where search
    #     results will be appended
    #   @yield [item, data] iterator for search results
    #   @yieldparam [String] item current search item
    #   @yieldparam [Hash] data search results for current search item
    #   @return [Array<Hash>] array of search results
    #
    # @see #find
    # @see #process_items
    def process(*args, &block)
      items, options = extract_options(args)

      items = items.map do |item|
        if File.exist?(item) && File.readable?(item)
          item = File.readlines(item).map(&:strip)
        elsif File.exist?(item)
          raise_error "Found unreadable item file: #{item}"
        end

        item
      end.flatten

      process_items(*items, options, &block)
    end

    protected

    # Check if the provided URL item is safe or unsafe?
    # @api private
    # @param [String, URI] item URL item being searched
    # @param [Hash] options options modifying search scope
    # @option options [Bool] smarter Disable smarter searching
    # @return [Symbol, String] reason and identified threat for this item
    #   or nil, if the item is considered to be safe
    def unsafe_url?(item, options = {})
      item = item.to_s.downcase.gsub(%r{\Ahttps?://}, '').chomp('/')
      return [:url, item] if in_pool?(:url, item)
      return unless options.fetch(:smarter, true)

      uri = URI.parse("http://#{item}")
      reason, found = unsafe_host?(uri.host)
      return [reason, found] if found

      reason, found = unsafe_ip?(uri.host)
      return [reason == :ip ? :ip : :ip_in_network, found] if found
    end

    # Check if the provided host item is safe or unsafe?
    # @api private
    # @param [String] item host item being searched
    # @param [Hash] _options options modifying search scope
    # @option options [Bool] smarter Disable smarter searching
    # @return [Symbol, String] reason and identified threat for this item
    #   or nil, if the item is considered to be safe
    def unsafe_host?(item, _options = {})
      item = item.to_s.downcase
      return [:host, item] if in_pool?(:host, item)
    end

    # Check if the provided IP is safe or unsafe?
    # @api private
    # @param [String] item IP being searched
    # @param [Hash] options options modifying search scope
    # @option options [Bool] smarter Disable smarter searching
    # @return [Symbol, String] reason and identified threat for this item
    #   or nil, if the item is considered to be safe
    def unsafe_ip?(item, options = {})
      return [:ip, item] if in_pool?(:ip, item)
      return unless options.fetch(:smarter, true)

      found = contained_in_network?(item)
      return [:in_network, found] if found
    end

    # Check if the provided network is safe or unsafe?
    # @api private
    # @param [String] item network being searched
    # @param [Hash] options options modifying search scope
    # @option options [Bool] smarter Disable smarter searching
    # @return [Symbol, String] reason and identified threat for this item
    #   or nil, if the item is considered to be safe
    def unsafe_network?(item, options = {})
      return [:network, item] if in_pool?(:network, item)
      return unless options.fetch(:smarter, true)

      found = contained_in_network?(item)
      return [:in_network, found] if found
    end

    # Check if the provided string is safe or unsafe?
    # @api private
    # @param [String] item string being searched
    # @param [Hash] _options options modifying search scope
    # @option options [Bool] smarter Disable smarter searching
    # @return [Symbol, String] reason and identified threat for this item
    #   or nil, if the item is considered to be safe
    def unsafe_unknown?(item, _options = {})
      item = item.to_s.downcase
      return [:unknown, item] if in_pool?(:unknown, item)
    end

    private

    def append_to_csv(results, path = nil)
      CSV.open(path, 'a') do |csv|
        results.each_pair do |item, res|
          csv << [item, res[:type], res[:safe], res[:reason], res[:identified]]
        end
      end
      results
    end

    def in_pool?(key, item)
      cache.send(key).include?(item)
    end

    def contained_in_network?(item)
      ip = IPAddress.parse(item)
      cache.network.detect { |net| IPAddress.parse(net).include?(ip) }
    rescue ArgumentError
      nil
    end

    def extract_options(args)
      opts = args.last.is_a?(Hash) ? args.pop : {}
      [args, opts]
    end
  end
end
