source 'https://rubygems.org'

gemspec

if ENV['BUNDLE_GEMFILE'] =~ /local/
  gem 'pg_partitioned', path: '../pg_partitioned'
  gem 'flex_records', path: './../../flex_records'
else
  # gem 'pg_partitioned', git: 'git@github.com:ruvzi/pg_partitioned.git', branch: 'rails6'
  # gem 'flex_records', git: 'git@github.com:ruvzi/flex_records.git', branch: 'master'
end

group :development, :test do
  gem 'thor'
  gem 'figaro'
  gem 'omniauth-github', '~> 2.0.0'
  gem 'omniauth-facebook', '~> 8.0.0'
  gem 'omniauth-google-oauth2', '~> 0.8.1'
  gem 'rack-cors', require: 'rack/cors'
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
