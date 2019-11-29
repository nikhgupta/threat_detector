# frozen_string_literal: true

module ThreatDetector
  module Utility
    def raise_error(error)
      raise ThreatDetector::Error, error
    end

    def sanitize_options(opts = {})
      opts = opts.to_h.map { |key, val| [key.to_sym, val] }.to_h
      opts[:working_directory] ||= ThreatDetector::DEFAULT_HOME
      opts[:feeds_config_path] ||= ThreatDetector::DEFAULT_CONFIG
      opts
    end

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

    def categorize_uri(str)
      regex = /\.+/ # really simple host regex to thwart unwanted strings
      str = "http://#{str}" unless str =~ %r{\Ahttps?://}
      uri = URI.parse(str)
      path = uri.path.chomp('/')
      path.empty? && uri.host =~ regex ? :host : :url
    rescue URI::InvalidURIError
      :unknown
    end

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
