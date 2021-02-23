# == Schema Information
#
# Table name: authentications
#
#  id         :bigint           not null, primary key
#  data       :text
#  deleted_at :datetime
#  expires_at :datetime
#  expiry     :integer
#  provider   :string           default("email"), not null
#  token      :string
#  tokens     :json
#  uid        :string           default(""), not null
#  created_at :datetime
#  updated_at :datetime
#  domain_id  :integer
#  user_id    :integer
#

require 'bcrypt'
class Authentication < PgPartitioned::ByDomainId
  self.primary_key = :id
  # include DeviseTokenAuth::Concerns::Strategy
  include DeviseTokenAuth::Concerns::AuthenticationOmniauthCallbacks

  include DeviseTokenAuth::Concerns::ActiveRecordSupport

  belongs_to :user
  acts_as_paranoid

  scope :provider, ->(provider) { where(provider: provider) }
  scope :uid,      ->(uid) { where.not(user_id: nil).where(uid: uid) }
  scope :domained, ->(domain) { where(domain_id: domain&.auth_domain_id) }

  serialize :data

  # unless table_exists? && self.columns_hash['tokens'] && self.columns_hash['tokens'].type.in?([:json, :jsonb])
  #   serialize :tokens, JSON
  # end

  # can't set default on text fields in mysql, simulate here instead.
  after_save :set_empty_token_hash
  after_initialize :set_empty_token_hash

  # get rid of dead tokens
  before_save :destroy_expired_tokens

  def create_token(client: nil, lifespan: nil, cost: nil, **token_extras)
    token = DeviseTokenAuth::TokenFactory.create(client: client, lifespan: lifespan, cost: cost)

    tokens[token.client] = {
      token:  token.token_hash,
      expiry: token.expiry
    }.merge!(token_extras)

    clean_old_tokens

    token
  end

  def valid_token?(token, client = 'default')
    return false unless tokens[client]
    return true if token_is_current?(token, client)
    return true if token_can_be_reused?(token, client)

    # return false if none of the above conditions are met
    false
  end

  def token_is_current?(token, client)
    # ghetto HashWithIndifferentAccess
    expiry     = tokens[client]['expiry'] || tokens[client][:expiry]
    token_hash = tokens[client]['token'] || tokens[client][:token]

    expiry && token &&
      DateTime.strptime(expiry.to_s, '%s') > Time.zone.now &&
      DeviseTokenAuth::Concerns::User.tokens_match?(token_hash, token)
  end

  # allow batch requests to use the previous token
  def token_can_be_reused?(token, client)
    # ghetto HashWithIndifferentAccess
    updated_at = tokens[client]['updated_at'] || tokens[client][:updated_at]
    last_token_hash = tokens[client]['last_token'] || tokens[client][:last_token]

    updated_at && last_token_hash &&
      updated_at.to_time > Time.zone.now - DeviseTokenAuth.batch_request_buffer_throttle &&
      DeviseTokenAuth::TokenFactory.token_hash_is_token?(last_token_hash, token)
  end

  # update user's auth token (should happen on each request)
  def create_new_auth_token(client = nil)
    now = Time.zone.now

    token = create_token(
      client: client,
      last_token: tokens.fetch(client, {})['token'],
      updated_at: now
    )

    update_auth_header(token.token, token.client)
  end

  def build_auth_header(token, client = 'default')
    # client may use expiry to prevent validation request if expired
    # must be cast as string or headers will break
    expiry = tokens[client]['expiry'] || tokens[client][:expiry]

    {
      DeviseTokenAuth.headers_names[:"access-token"] => token,
      DeviseTokenAuth.headers_names[:"token-type"]   => 'Bearer',
      DeviseTokenAuth.headers_names[:"client"]       => client,
      DeviseTokenAuth.headers_names[:"expiry"]       => expiry.to_s,
      DeviseTokenAuth.headers_names[:"uid"]          => uid
    }
  end

  def update_auth_header(token, client = 'default')
    headers = build_auth_header(token, client)
    clean_old_tokens
    save!

    headers
  end


  def build_auth_url(base_url, args)
    args[:uid]    = self.uid
    args[:expiry] = self.tokens[args[:client_id]]['expiry'] || self.tokens[args[:client_id]][:expiry]

    url = DeviseTokenAuth::Url.generate(base_url, args)
    url.gsub!('https', 'http') if URI(url).scheme.eql?('https') && (subdomain = ActionDispatch::Http::URL.extract_subdomain(URI(url).host, 1)).present? && !subdomain.eql?('www')
    url
  end


  def extend_batch_buffer(token, client)
    tokens[client]['updated_at'] = Time.zone.now
    update_auth_header(token, client)
  end

  protected

  def set_empty_token_hash
    return unless has_attribute?(:tokens)
    self.tokens ||= {}
  end

  def destroy_expired_tokens
    return unless self.tokens.present?

    self.tokens.delete_if do |_cid, v|
      DateTime.strptime((v[:expiry] || v['expiry']).to_s, '%s') < Time.now
    end
  end

  def remove_tokens_after_user_password_reset
    return if tokens.blank? || !tokens.many?

    client, token_data = tokens.max_by { |_cid, v| v[:expiry] || v['expiry'] }
    self.tokens = { client => token_data }
    save
  end

  def max_client_tokens_exceeded?
    tokens.length > DeviseTokenAuth.max_number_of_devices
  end

  def clean_old_tokens
    if tokens.present? && max_client_tokens_exceeded?
      # Using Enumerable#sort_by on a Hash will typecast it into an associative
      #   Array (i.e. an Array of key-value Array pairs). However, since Hashes
      #   have an internal order in Ruby 1.9+, the resulting sorted associative
      #   Array can be converted back into a Hash, while maintaining the sorted
      #   order.
      self.tokens = tokens.sort_by { |_cid, v| v[:expiry] || v['expiry'] }.to_h

      # Since the tokens are sorted by expiry, shift the oldest client token
      #   off the Hash until it no longer exceeds the maximum number of clients
      tokens.shift while max_client_tokens_exceeded?
    end
  end
end
