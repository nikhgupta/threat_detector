# ThreatDetector

ThreatDetector allows you to identify threats using feeds from ThreatFeeds.io

## Features

- Insanely fast matching against threat database using Trie structures
- Smarter searches by classifying threats into several categories, such as IP, networks, hosts, etc.
- Knows that:
    - URLs can be a threat if their IP or host is a threat
    - IPs is threat if present in CIDR networks which are a threat
    - A network is a threat if their wider network is a threat
    - TODO: A host is a threat if the IP it resolves to is a threat
    - TODO: An IP is a threat if the host it resolves to is a threat
    - and so on..

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

You can use CLI tool to download, and build the cache required for performing searches.

Otherwise, in your Ruby code, you can use the following to download and build your cache.
This will download the threats database and build a cache for you. Default path for files
downloaded via these calls is `~/.threat_detector/`, but it can easily be switched via
options to these methods.

```ruby
# download entries from various feeds from ThreatFeeds.io
ThreatDetector.download do |name, _, sc|
    puts "Scraped feed for #{name}"
end

# compress the entries so obtained in a cache for quick searches later
stats = ThreatDetector.build_cache
print(stats)
```

Afterwards, if you plan on making a few searches, instantiate `ThreatDetector::Search` class,
which will load a copy of this database in memory. If you have a custom path for downloaded
files or your cache, your must provide them as options to this class, as well.

```ruby
options = { working_directory: `/path/to/cache/directory` }
search = ThreatDetector::Search.new(options) # loads the cache in-memory
search.run(%w[nikhgupta.com 123.123.123.123 example.com/page 123.123.123.123/30 example.com https://exmaple.com/some-page])
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nikhgupta/threat_detector. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the ThreatDetector project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/nikhgupta/threat_detector/blob/master/CODE_OF_CONDUCT.md).
