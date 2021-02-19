module DeviseTokenAuth::Concerns::Strategy
  extend ActiveSupport::Concern

  included do
    before_save :current_token_reload, if: :data_changed?
    # before_save :long_token_load!, if: :token_changed? # TODO: add after use not long-live token

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
    case provider
      when 'facebook' then facebook_client_api
      when 'vkontakte' then vkontakte_client_api
      else return nil
    end
  end

  def facebook_client_api
    app_graph = Koala::Facebook::API.new(ENV['auth_facebook_access_token'])
    Koala::Facebook::API.new(token) if app_graph.debug_token(self.token)['data']['is_valid']
    # add long live token if issued_at nil
  end

  def vkontakte_client_api
    VkontakteApi::Client.new(ENV['auth_vkontakte_access_token'])
  end

  def long_token_load!
    case provider
      when 'facebook' then load_facebook_long_token!
      when 'vkontakte' then load_vkontakte_long_token!
      else return true
    end
  end

  def load_facebook_long_token!
    oauth = Koala::Facebook::OAuth.new(ENV['auth_facebook_key'],ENV['auth_facebook_secret'])
    begin
      new_access_info = oauth.exchange_access_token_info(token)
      new_access_token = new_access_info['access_token']
      new_access_expires_at = DateTime.now + new_access_info['expires_in'].to_i.seconds

      self.token = new_access_token
      self.expiry = data.credentials.expires_at
      self.expires_at = new_access_expires_at
    rescue
    end
  end

  def load_vkontakte_long_token!
    # TODO
    true
  end
end