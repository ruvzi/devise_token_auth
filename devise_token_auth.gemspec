require_relative 'lib/devise_token_auth/version'

Gem::Specification.new do |spec|
  spec.name        = 'devise_token_auth'
  spec.version     = DeviseTokenAuth::VERSION
  spec.authors     = ['Lynn Hurley']
  spec.email       = ['lynn.dylan.hurley@gmail.com']
  spec.homepage    = 'http://github.com/lynndylanhurley/devise_token_auth'
  spec.summary     = 'Token based authentication for rails. Uses Devise + OmniAuth.'
  spec.description = 'For use with client side single page apps such as the venerable https://github.com/lynndylanhurley/ng-token-auth.'
  spec.license     = 'WTFPL'

  spec.files      = Dir['{app,config,db,lib}/**/*', 'LICENSE', 'Rakefile', 'README.md']
  spec.test_files = Dir['test/**/*']

  spec.add_dependency 'rails', '~> 6.1.3'
  spec.add_dependency 'devise', '>= 4.7.3', '< 5'
  spec.add_dependency 'bcrypt', '~> 3.0'

  spec.add_dependency 'pg', '~> 1.2.3'
  spec.add_dependency 'omniauth', '~> 1', '< 2'
  spec.add_dependency 'omniauth-oauth2', '~> 1.7.1'
  spec.add_dependency 'omniauth-vkontakte', '~> 1.7.0'
  spec.add_dependency 'omniauth-instagram', '~> 1.3.0'
  spec.add_dependency 'omniauth-mailru', '~> 1.0.0'
  spec.add_dependency 'omniauth-odnoklassniki', '~> 0.0.8'
  spec.add_dependency 'omniauth-facebook', '~> 8.0.0'
  spec.add_dependency 'omniauth-twitter', '~> 1.4.0'
  spec.add_dependency 'omniauth-vimeo', '~> 2.0.0'
  spec.add_dependency 'omniauth-google-oauth2', '~> 0.8.1'
  spec.add_dependency 'omniauth-youtube', '~> 2.1.0'
  spec.add_dependency 'omniauth-tumblr', '~> 1.2'
  spec.add_dependency 'draper', '~> 4.0.1'
  spec.add_dependency 'paranoia', '~> 2.4.3'
  spec.add_dependency 'delayed_job_active_record', '~> 4.1.5'
end
