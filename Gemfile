source 'https://rubygems.org'

gemspec

if ENV['BUNDLE_GEMFILE'] =~ /local/
  gem 'pg_partitioned', path: './../gems/pg_partitioned'
else
  gem 'pg_partitioned', git: 'git@github.com:ruvzi/pg_partitioned.git', branch: 'master'
end

group :development, :test do
  gem 'thor'
  gem 'figaro'
  gem 'omniauth-github'
  gem 'omniauth-facebook'
  gem 'omniauth-google-oauth2'
  gem 'rack-cors',              require: 'rack/cors'
  gem 'attr_encrypted'

  # testing
  #gem 'spring'
  gem 'pry'
  gem 'pry-remote'
  gem 'minitest'
  gem 'minitest-rails'
  gem 'minitest-focus'
  gem 'minitest-reporters'
  gem 'guard'
  gem 'guard-minitest'
  gem 'faker'
  gem 'fuzz_ball'
  gem 'mocha'
end

# code coverage, metrics
group :test do
  gem 'codeclimate-test-reporter', require: false
end
