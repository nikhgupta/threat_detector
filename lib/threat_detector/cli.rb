# frozen_string_literal: true

module ThreatDetector
  class CLI < Thor
    include Thor::Actions

    desc 'scrape', 'Scrape and download threats identified by ThreatFeeds.io'
    method_option :refresh, type: :boolean,
                            default: false,
                            alias: '-r',
                            desc: 'Refresh feeds even if they already exist'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    method_option :feeds_config_path, type: :string,
                                      aliases: '-c',
                                      default: ThreatDetector::DEFAULT_CONFIG,
                                      desc: 'Scraping config for various feeds'
    def scrape
      ThreatDetector.download(options) do |item, sc|
        if sc.reason
          say_status 'Warning', "#{sc.reason} for tracker: #{item['name']}", :yellow
        else
          say_status 'Success', "Added #{"%6d" % sc.size} entries for tracker: #{item['name']}"
        end
      end
    end

    desc 'cache', 'Build local cache of threat entries from scraped feeds'
    method_option :refresh, type: :boolean,
                            default: false,
                            alias: '-r',
                            desc: 'Refresh feeds even if they already exist'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    def cache
      info = ThreatDetector.build_cache(options) do |file, data|
        status = File.basename(file, '.*').split('-')[0]
        print_stats data, status: status, padding: 32
      end

      print_stats info
    end

    desc 'search [*KEYs]', 'Search database of threat entries'
    method_option :save, type: :boolean,
                         aliases: '-s',
                         default: false,
                         desc: 'Save the results as csv'
    method_option :print, type: :boolean,
                          aliases: '-p',
                          default: false,
                          desc: 'Print the results in a tabular/csv format'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    def search(*keys)
      info = ThreatDetector.search(keys, options) do |key, res|
        if !res[:safe]
          say_status 'Found', key, :yellow
        else
          say_status 'Safe', key
        end
      end

      info = info.group_by { |_key, res| res[:safe] ? 'safe' : 'threat' }
      print_stats info, status: 'STATUS'
    end

    private

    def print_stats(info, status: 'CACHE', padding: nil)
      str = info.map { |key, val| "#{key}=#{val}" }.join(', ')
      status = padding ? "%#{padding}s" % status : status
      say_status status, str
    end
  end
end
