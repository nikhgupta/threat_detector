# frozen_string_literal: true

module ThreatDetector
  module Utility
    def raise_error(error)
      raise ThreatDetector::Error, error
    end

    # Sanitize options for use across all ThreatDetector instances.
    def sanitize_options(opts = {})
      opts = opts.to_h.map { |key, val| [key.to_sym, val] }.to_h
      opts[:working_directory] ||= ThreatDetector::DEFAULT_HOME
      opts[:feeds_config_path] ||= ThreatDetector::DEFAULT_CONFIG
      opts
    end

    # common interface to fetch a page using curl
    #
    # NOTE: Most other libraries had issues parsing some of the feed
    # URLs, or even in connecting with some. CURL had success in all
    # cases/feeds, which is why chosing it over others that I tried,
    # e.g. Faraday, http.rb, Mechanize, open-uri, etc.
    #
    # I am guessing that `Net::HTTP` based libraries have an underlying
    # problem connecting to these IPs or are being banned by the server.
    #
    def fetch_page(url, options = {}, &block)
      return if url.to_s.strip.empty?

      options = ThreatDetector::DEFAULT_CURL_OPTIONS.merge(options)
      @page = Curl::Easy.perform(url) do |req|
        options.each do |key, val|
          req.send("#{key}=", val)
        end

        block&.call(req)
      end
    end

    # Categorize a given URL as a Host name or URL.
    # We use a fairly simple regex to validate hostnames here,
    # since that suffices for the use-case we have here.
    #
    def categorize_uri(str)
      regex = /\.+/ # really simple host regex to thwart unwanted strings
      str = "http://#{str}" unless str =~ %r{\Ahttps?://}
      uri = URI.parse(str)
      path = uri.path.chomp('/')
      path.empty? && uri.host =~ regex ? :host : :url
    rescue URI::InvalidURIError
      :unknown
    end

    # Categorize a given string as an IP, Network, Host or URL
    # based on its contents.
    #
    def categorize_ip_or_uri(entry)
      ip = IPAddress.parse(entry)
      if ip.network? && ip.size == 1
        ip.mapped? ? :url : :ip
      elsif ip.network?
        :network
      else
        :ip
      end
    rescue ArgumentError
      categorize_uri(entry)
    end
  end
end
