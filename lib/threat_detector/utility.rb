# frozen_string_literal: true

module ThreatDetector
  # Utility module for this gem.
  #
  # This module is included in several classes, and provides several utility
  # methods.
  module Utility
    # Raise an {ThreatDetector::Error} with the given message.
    #
    # @param [String] error error message for the error
    # @raise [ThreatDetector::Error] always
    #
    # @return [ThreatDetector::Error]
    def raise_error(error)
      raise ThreatDetector::Error, error
    end

    # Sanitize options for use in classes under {ThreatDetector} namespace.
    #
    # @param [Hash] opts options received from the user
    # @option opts [String] :working_directory directory to download feeds and build cache in
    # @option opts [String] :feeds_config_path path to YAML file with scraping config
    #
    # @return [Hash] sanitized options with defaults, etc.
    #
    # The default options are:
    #   working_directory: ~/.threat_detector
    #   feeds_config_path: <gem_path>/threat_detector/feeds.yaml
    def sanitize_options(opts = {})
      opts = opts.to_h.map { |key, val| [key.to_sym, val] }.to_h
      opts[:working_directory] ||= ThreatDetector::DEFAULT_HOME
      opts[:feeds_config_path] ||= ThreatDetector::DEFAULT_CONFIG
      FileUtils.mkdir_p(opts[:working_directory])
      opts
    end

    # Working directory for this instance.
    def working_directory
      @options[:working_directory]
    end

    # Path to YAML config file specifying scraping settings.
    # This file is used by {ThreatDetector::Scraper} and
    # {ThreatDetector::Downloader}
    def feeds_config_path
      @options[:feeds_config_path]
    end

    # Explicitely, set the refresh status for this scraper.
    # Setting this to `true` will ignore existing (cached) scraped data,
    # and re-scrape the threat entries.
    # !@attribute [w] refresh whether to ignore existing scraped data?
    def refresh=(refresh)
      @options[:refresh] = refresh
    end

    def refresh?
      @options[:refresh]
    end

    # Common interface for fetching a page using Curl.
    #
    # @note Most other libraries had issues parsing some of the feed
    #   URLs, or even in connecting with some. CURL had success in all
    #   cases/feeds, which is why I chose it over others that I tried,
    #   e.g. Faraday, http.rb, Mechanize, open-uri, etc.
    #
    #   I am guessing that `Net::HTTP` based libraries have an underlying
    #   problem connecting to these IPs or are being banned by the server.
    #
    # @param [String, URI, #to_s] url URL to fetch page for
    # @param [Hash] options curl options to pass to Curb library
    # @return [Curl::Easy]
    #
    # @yield [request] Curl request for further processing before fetch
    # @yieldparam [Curl::Easy] request request object before fetch
    #
    # @see https://github.com/taf2/curb Curb Library ReadMe
    def fetch_page(url, options = {}, &block)
      return if url.to_s.strip.empty?

      options = ThreatDetector::DEFAULT_CURL_OPTIONS.merge(options)
      @page = Curl::Easy.perform(url.to_s) do |req|
        options.each do |key, val|
          req.send("#{key}=", val)
        end

        block&.call(req)
      end
    end

    # Categorize a given string as a Host name or URL.
    #
    # @note We use a fairly simple regex to validate hostnames here,
    #   since that suffices for the use-case (feeds) we have here.
    #
    # @param (see #categorize_ip_or_uri)
    # @return [Symbol] categorized category for this string
    def categorize_uri(str)
      regex = /\.+/ # really simple host regex to thwart unwanted strings
      str = "http://#{str}" unless str.to_s =~ %r{\Ahttps?://}
      uri = URI.parse(str.to_s)
      path = uri.path.chomp('/')
      return :unknown if (uri.host =~ regex).nil?

      path.empty? ? :host : :url
    rescue URI::InvalidURIError
      :unknown
    end

    # Categorize a given string as an IP, Network, Host or URL
    # based on its contents.
    #
    # We parse the string with IPAddress library, and try to assign it
    # a category from IP, Network or a URL. On failure, we try to assign
    # the category via {#categorize_uri}
    #
    # This method is used to decide which item in a feed goes to which subset
    # in our cache, and also, to identify which heuristics to use to identify
    # or search a given search term in our cache.
    #
    # @param [String, URI, #to_s] str String to categorize
    # @return [Symbol] categorized category for this string
    #
    # @see https://github.com/ipaddress-gem/ipaddress IPAddress Library ReadMe
    def categorize_ip_or_uri(str)
      if valid_ip?(str)
        ip = IPAddress.parse(str)
        if ip.network? || ip.size > 1 || valid_network?(str)
          :network
        else
          :ip
        end
      else
        categorize_uri(str)
      end
    end

    def valid_ip?(str)
      return :ipv4 if IPAddress.valid_ipv4?(str)
      return :ipv6 if IPAddress.valid_ipv6?(str)

      valid_network?(str)
    end

    def valid_network?(str)
      ip, mask = str.split('/', 2)
      return false unless mask.to_i.to_s == mask && mask.to_i <= 32

      IPAddress.valid_ipv4?(ip)
    end
  end
end
