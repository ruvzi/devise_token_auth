# == Schema Information
#
# Table name: authentications
#
#  id         :integer          not null, primary key
#  user_id    :integer
#  provider   :string           default("email"), not null
#  uid        :string           default(""), not null
#  data       :text
#  tokens     :json
#  created_at :datetime
#  updated_at :datetime
#  deleted_at :datetime
#  token      :string
#  expiry     :integer
#  expires_at :datetime
#  domain_id  :integer
#
# Indexes
#
#  index_authentications_on_domain_id                        (domain_id)
#  index_authentications_on_uid_and_provider_and_deleted_at  (uid,provider,deleted_at) UNIQUE
#
# Foreign Keys
#
#  fk_rails_...  (domain_id => domains.id)
#

require 'bcrypt'
class Authentication < ActiveRecord::Base
  include DeviseTokenAuth::Concerns::Strategy

  belongs_to :user
  acts_as_paranoid

  scope :provider, -> (provider){where(provider: provider)}
  scope :uid,      -> (uid){where.not(user_id: nil).where(uid: uid)}
  scope :domained, ->(domain) { where(domain_id: domain&.id ) }

  validates_presence_of :uid, if: Proc.new { |u| u.provider != 'email' }

  serialize :data

  unless table_exists? && self.columns_hash['tokens'] && self.columns_hash['tokens'].type.in?([:json, :jsonb])
    serialize :tokens, JSON
  end

  # can't set default on text fields in mysql, simulate here instead.
  after_save :set_empty_token_hash
  after_initialize :set_empty_token_hash

  # keep uid in sync with email
  before_save :sync_uid

  # get rid of dead tokens
  before_save :destroy_expired_tokens

  def valid_token?(token, client_id='default')
    client_id ||= 'default'

    return false unless self.tokens[client_id]

    return true if token_is_current?(token, client_id)
    return true if token_can_be_reused?(token, client_id)

    # return false if none of the above conditions are met
    false
  end

  def token_is_current?(token, client_id)
    # ghetto HashWithIndifferentAccess
    expiry     = self.tokens[client_id]['expiry'] || self.tokens[client_id][:expiry]
    token_hash = self.tokens[client_id]['token'] || self.tokens[client_id][:token]

    expiry && token &&
      DateTime.strptime(expiry.to_s, '%s') > Time.now &&
      DeviseTokenAuth::Concerns::User.tokens_match?(token_hash, token)
  end

  # allow batch requests to use the previous token
  def token_can_be_reused?(token, client_id)
    # ghetto HashWithIndifferentAccess
    updated_at = self.tokens[client_id]['updated_at'] || self.tokens[client_id][:updated_at]
    last_token = self.tokens[client_id]['last_token'] || self.tokens[client_id][:last_token]

    updated_at && last_token &&
      Time.parse(updated_at) > Time.now - DeviseTokenAuth.batch_request_buffer_throttle &&
      ::BCrypt::Password.new(last_token) == token
  end

  # update user's auth token (should happen on each request)
  def create_new_auth_token(client_id = nil)
    client_id  ||= SecureRandom.urlsafe_base64(nil, false)
    last_token ||= nil
    token        = SecureRandom.urlsafe_base64(nil, false)
    token_hash   = ::BCrypt::Password.create(token)
    expiry       = (Time.now + DeviseTokenAuth.token_lifespan).to_i

    if self.tokens[client_id] and self.tokens[client_id]['token']
      last_token = self.tokens[client_id]['token']
    end

    self.tokens[client_id] = {
        token:      token_hash,
        expiry:     expiry,
        last_token: last_token,
        updated_at: Time.now
    }

    self.save!

    build_auth_header(token, client_id)
  end

  def build_auth_header(token, client_id='default')
    # client may use expiry to prevent validation request if expired
    # must be cast as string or headers will break
    self.tokens ||= {}
    self.tokens[client_id] ||= {}
    expiry = self.tokens[client_id]['expiry'] || self.tokens[client_id][:expiry]

    {
        'access-token' => token,
        'token-type'   => 'Bearer',
        client:           client_id,
        expiry:           expiry.to_s,
        uid:              self.uid
    }
  end


  def build_auth_url(base_url, args)
    args[:uid]    = self.uid
    args[:expiry] = self.tokens[args[:client_id]]['expiry'] || self.tokens[args[:client_id]][:expiry]

    url = DeviseTokenAuth::Url.generate(base_url, args)
    url.gsub!('https', 'http') if URI(url).scheme.eql?('https') && (subdomain = ActionDispatch::Http::URL.extract_subdomain(URI(url).host, 1)).present? && !subdomain.eql?('www')
    url
  end


  def extend_batch_buffer(token, client_id)
    self.tokens[client_id]['updated_at'] = Time.now
    self.save!

    build_auth_header(token, client_id)
  end

  protected

  def set_empty_token_hash
    return unless has_attribute?(:tokens)
    self.tokens ||= {}
  end

  def sync_uid
    return unless (new_uid = self.user.try(:email)).present? && provider.eql?('email')
    self.uid = new_uid
  end

  def destroy_expired_tokens
    return unless self.tokens.present?
    self.tokens.delete_if do |cid, v|
      expiry = v[:expiry] || v['expiry']
      DateTime.strptime(expiry.to_s, '%s') < Time.now
    end
  end
end
