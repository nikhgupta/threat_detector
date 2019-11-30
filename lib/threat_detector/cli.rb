# frozen_string_literal: true

module ThreatDetector
  class CLI < Thor
    include Thor::Actions

    desc 'scrape', 'Scrape and download threats identified by ThreatFeeds.io'
    method_option :refresh, type: :boolean, default: false,
                            desc: 'Force downloading of fresh threat feeds'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    method_option :feeds_config_path, type: :string,
                                      aliases: '-c',
                                      default: ThreatDetector::DEFAULT_CONFIG,
                                      desc: 'Scraping config for various feeds'
    def scrape
      info = ThreatDetector.download(options) do |name, _row, sc|
        if sc.reason
          say_status 'Warning', "#{sc.reason} for tracker: #{name}", :yellow
        else
          say_status 'Success', "Added #{sc.size} entries for tracker: #{name}"
        end
      end

      print_stats info
    end

    desc 'build', 'Re-build database of threat entries from local cache'
    method_option :refresh, type: :boolean, default: false,
                            desc: 'Force downloading of fresh threat feeds'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    def build
      info = ThreatDetector.build_cache(options) do |file, data|
        status = File.basename(file, '.*').split('-')[0]
        print_stats data, status: status, padding: 32
      end

      print_stats info
    end

    desc 'search [*KEYs]', 'Search database of threat entries'
    method_option :working_directory, type: :string,
                                      aliases: '-w',
                                      default: ThreatDetector::DEFAULT_HOME,
                                      desc: 'Path to save threat feeds in'
    def search(*keys)
      info = ThreatDetector.search(keys, options) do |key, found|
        if found
          say_status 'Found', key, :yellow
        else
          say_status 'Safe', key
        end
      end

      info = info.group_by { |_key, found| found ? 'threat' : 'safe' }
      print_stats info, status: 'STATUS'
    end

    private

    def print_stats(info, status: 'CACHE', padding: nil)
      str = info.map { |key, val| "#{key}=#{val.length}" }.join(', ')
      status = padding ? "%#{padding}s" % status : status
      say_status status, str
    end
  end
end
