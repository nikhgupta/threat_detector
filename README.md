# ThreatDetector

Check IPs, Hosts, Networks or URLs for possible threats using feeds from
ThreatFeeds.io

ThreatDetector creates a local cache of threats by downloading ThreatFeeds.io
feeds, parsing them, and storing them in
[Trie](https://en.wikipedia.org/wiki/Trie) structures to allow for efficient
and fast searches in this huge database of threats.

ThreatDetector tries to be smart in understanding that the database may not
necessarily contain the exact search term, and often, employs logic in
deciding whether a given IP, network, host or URL is a threat. For example,
in addition to directly matching threats in this database, it knows that:

- An IP is a threat if it belongs to an identified network.
- A network is a threat if it belongs to a wider identified network.
- An IP is a threat if the hostname it resolves to is marked as a threat.
- A host can be a threat if the IP it resolves to is marked as a threat.
- A url can be a threat if its hostname or IP is marked as a threat.
- etc.

Furthermore, any threat that is identified is returned with a reason for the
same, allowing you to also identify why a particular IP, host, network or URL
was marked as a threat. You can, optionally, choose to disable smarter
searching (only match directly with database), disable resolving IP/host to
corresponding host/IP for matching, etc.

Lastly, feeds from ThreatFeeds.io all use different formatting to display the
threats, but have a generic structure. We parse these feeds using a single
method call, where applicable, and resort to parsing them via a custom method
where formatting differs significantly in {ThreatDetector::Scraper#parse}. To
make this work, we use a YAML config that provides us with parsing settings
for scraper for each feed. A working YAML config file is provided with this
gem, but you can use a custom configuration by providing a
`:feeds_config_path` option when instantiating the scraper/downloader. To
read more about what each YAML config option does, please see
{ThreatDetector::Scraper#reset!}.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'threat_detector'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install threat_detector

## Usage

In your Ruby code, you can use ThreatDetector by downloading the feeds and building your
cache, first. Afterwards, you should re-download the feeds from time to time, and
re-build (update) your cache.

```ruby
# download entries from various feeds from ThreatFeeds.io
ThreatDetector.download do |name, _info, scraper|
    puts "Skipping feed #{name} due to #{scraper.reason}" if scraper.reason
end

# refresh downloaded entries from time to time
ThreatDetector.download(refresh: true)

# build our local cache of threats
stats = ThreatDetector.build_cache
print(stats)
```

Once the cache has been built for you, you can use `ThreatDetector.stats` to
get the stats on how many entries of each subset (IP, host, network or URL)
exist in your cache for informational purposes.

When searching, ThreatDetector loads the entire cache in memory, which is why its
a good idea to instantiate the `ThreatDetector::Search` class once, and re-use it
for making searches. You can pass an array of search terms, or a file containing
search terms. You can, optionally, save the results obtained to a file on
disk. You must supply the path to your custom cache directory, if any.

```ruby
options = {}
# options = { working_directory: `/path/to/directory` }
search = ThreatDetector::Search.new(options) # loads the cache in-memory

# Search for terms in the given file, and save/append the results to the given CSV file.
# Note that, `#process` can take both file paths as well as search terms as arguments, and
# gives preferences to file paths.
#
# If you are not searching for search terms in files, you can use `#process_items` to process
# everything as search terms, directly.
search.process "/path/to/file/containing/search/terms.txt", save: '/path/to/save/file.csv'

# Search for the specified terms
res = search.process "nikhgupta.com", "123.123.123.123", "badhost.com/page", "123.123.123.123/28", "http://example.com/page"
res['nikhgupta.com']    # => { safe: true, type: :host }
res['badhost.com/page'] # => { safe: false, type: :url, reason: :host, identified: 'badhost.com' }
```

By default, we resolve hostname or IP to corresponding IP or hostname. You can disable this feature, which
will decrease response time for some searches at the cost of marking them as safe.

Specifically, this turns off:
- A host can be a threat if the IP it resolves to is marked as a threat.
- An IP is a threat if the hostname it resolves to is marked as a threat.

```ruby
res = search.process "hostwithbadip.com"
res['hostwithbadip.com'] # => { safe: false, type: :host, reason: :resolved_ip, identified: '143.101.123.102' }

res = search.process "hostwithbadip.com", resolve: false
res['hostwithbadip.com'] # => { safe: true, type: :host }
```

By default, some logics are applied when searching for a term in the database (outlined above).
You can disable all these logics, and restrict the searches to matching entries in the database
alone. This disables some heuristics in identifying threats, and is not recommended, in general.
Note that, this does not disable resolving of IP/hosts to host/IPs and must be done, separately.

Specifically, this turns off:
- An IP is a threat if it belongs to an identified network.
- A network is a threat if it belongs to a wider identified network.
- A url can be a threat if its hostname or IP is marked as a threat.

```ruby
res = search.process "hostwithbadip.com/page", "123.123.123.123/30"
res['hostwithbadip.com/page'] # => { safe: false, type: :url, reason: :resolved_ip, identified: '143.101.123.102' }
res['123.123.123.123/30'] # => { safe: false, type: :network, reason: :wider_network, identified: '123.123.123.123/24' }

res = search.process "badhost.com/page", "123.123.123.123/30", smarter: false
res['hostwithbadip.com/page'] # => { safe: false, type: :url, reason: :resolved_ip, identified: '143.101.123.102' }
res['123.123.123.123/30'] # => { safe: true, type: :network }
```

## CLI Usage

You can use CLI tool to download, and build the cache required for performing searches. Afterwards, you should be able to supply it with a list of search terms or supply a file containing your search terms to identify threats. Each search term will be displayed in the console along with whether it was identified as a threat, and along with the reason for the same.

Threat database will be downloaded and cached, by default, in `~/.threat_detector/` directory, and you can change this when downloading and caching the database. This CLI tool also provides additional options - please, check all CLI options for the same.

```bash
➲ threat_detector help
Commands:
  threat_detector help [COMMAND]  # Describe available commands or one specific com...
  threat_detector scrape          # Scrape and download threats identified by Threa...
  threat_detector cache           # Build local cache of threat entries from scrape...
  threat_detector search [*KEYs]  # Search database of threat entries
  ...
```

```bash
➲ threat_detector help scrape
Usage:
  threat_detector scrape

Options:
      [--refresh], [--no-refresh]              # Force downloading of fresh threat feeds
  -w, [--working-directory=WORKING_DIRECTORY]  # Path to save threat feeds in
                                               # Default: <home>/.threat_detector
  -c, [--feeds-config-path=FEEDS_CONFIG_PATH]  # Scraping config for various feeds
                                               # Default: <gem_home>/threat_detector/feeds.yaml

Scrape and download threats identified by ThreatFeeds.io
```

A typical flow for identifying threats via CLI would be:

```bash
threat_detector scrape            # first time - setup
threat_detector scrape --refresh  # refresh threat feeds from time to time
threat_detector cache             # build cache from locally downloaded threat feeds
threat_detector search /absolute/path/to/file/containing/search/terms.txt --save /path/to/save/file.csv
threat_detector search nikhgupta.com 123.123.123.123 example.com/page 123.123.123.123/28 http://example.com/page --print
```

## TODO

- [x] ..trimmed..
- [x] Complete specs for `ThreatDetector::Search`
- [x] Allow saving of search results to a file
- [ ] Allow to specify manual entries to be added as threats in the cache.
- [ ] Allow resolving host/IPs to IP/hosts for better searches.
- [ ] Push to rubygems, rubydoc and travis.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nikhgupta/threat_detector. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the ThreatDetector project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nikhgupta/threat_detector/blob/master/CODE_OF_CONDUCT.md).
