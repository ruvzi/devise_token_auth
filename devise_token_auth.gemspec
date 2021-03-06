$:.push File.expand_path('../lib', __FILE__)

# Maintain your gem's version:
require 'devise_token_auth/version'

# Describe your gem and declare its dependencies:
Gem::Specification.new do |s|
  s.name        = 'devise_token_auth'
  s.version     = DeviseTokenAuth::VERSION
  s.authors     = ['Lynn Hurley']
  s.email       = ['lynn.dylan.hurley@gmail.com']
  s.homepage    = 'http://github.com/lynndylanhurley/devise_token_auth'
  s.summary     = 'Token based authentication for rails. Uses Devise + OmniAuth.'
  s.description = 'For use with client side single page apps such as the venerable https://github.com/lynndylanhurley/ng-token-auth.'
  s.license     = 'WTFPL'

  s.files      = Dir['{app,config,db,lib}/**/*', 'LICENSE', 'Rakefile', 'README.md']
  s.test_files = Dir['test/**/*']

  s.add_dependency 'rails', '4.2.11.1'
  s.add_dependency 'devise', '~> 4.7.1'
  s.add_dependency 'omniauth-oauth2', '~> 1.6.0'
  s.add_dependency 'draper', '~> 2.1.0'
  s.add_dependency 'paranoia', '~> 2.4.2'
  s.add_dependency 'apipie-rails', '~> 0.5.16'
  s.add_dependency 'delayed_job_active_record', '~> 4.1.3'

  s.add_development_dependency 'sqlite3', '~> 1.3'
  s.add_development_dependency 'pg', '~> 0.21.0'
end
