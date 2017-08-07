module DeviseTokenAuth::Concerns::Strategy
  extend ActiveSupport::Concern

  included do
    before_save :current_token_reload, if: :data_changed?
    # before_save :long_token_load!, if: :token_changed?

    attr_writer :provider_api
  end

  def provider_api
    @provider_api ||= init_provider_api
  end

  private

  def current_token_reload
    return unless data.present?
    self.token = data.credentials.token
    self.expiry = data.credentials.expires_at
    self.expires_at = DateTime.strptime(self.expiry.to_s, '%s')
  end

  def init_provider_api
    long_token_load!
    case provider
      when 'facebook'
        Koala::Facebook::API.new(token)
      when 'vkontakte' then load_vkontakte_long_token!
      else return true
    end
  end

  def long_token_load!
    case provider
      when 'facebook' then load_facebook_long_token!
      when 'vkontakte' then load_vkontakte_long_token!
      else return true
    end
  end

  def load_facebook_long_token!
    oauth = Koala::Facebook::OAuth.new(ENV['auth_facebook_key'],  ENV['auth_facebook_secret'])
    oauth.exchange_access_token_info token
  end

  def load_vkontakte_long_token!
    # TODO
    true
  end
end