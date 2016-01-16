require 'bcrypt'
class Authentication < ActiveRecord::Base
  belongs_to :user

  scope :provider, -> (provider){where(provider: provider)}
  scope :uid,      -> (uid){where(uid: uid)}

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
  before_create :sync_uid

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

    true if (
        # ensure that expiry and token are set
    expiry and token and

        # ensure that the token has not yet expired
        DateTime.strptime(expiry.to_s, '%s') > Time.now and

        # ensure that the token is valid
        DeviseTokenAuth::Concerns::User.tokens_match?(token_hash, token)
    )
  end

  # allow batch requests to use the previous token
  def token_can_be_reused?(token, client_id)
    # ghetto HashWithIndifferentAccess
    updated_at = self.tokens[client_id]['updated_at'] || self.tokens[client_id][:updated_at]
    last_token = self.tokens[client_id]['last_token'] || self.tokens[client_id][:last_token]


    true if (
        # ensure that the last token and its creation time exist
    updated_at and last_token and

        # ensure that previous token falls within the batch buffer throttle time of the last request
        Time.parse(updated_at) > Time.now - DeviseTokenAuth.batch_request_buffer_throttle and

        # ensure that the token is valid
        ::BCrypt::Password.new(last_token) == token
    )
  end

  # update user's auth token (should happen on each request)
  def create_new_auth_token(client_id=nil)
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

    DeviseTokenAuth::Url.generate(base_url, args)
  end


  def extend_batch_buffer(token, client_id)
    self.tokens[client_id]['updated_at'] = Time.now
    self.save!

    build_auth_header(token, client_id)
  end

  protected

  def set_empty_token_hash
    self.tokens ||= {} if has_attribute?(:tokens)
  end

  def sync_uid
    self.uid = self.user.email if provider.eql?('email')
  end

  def destroy_expired_tokens
    if self.tokens
      self.tokens.delete_if do |cid, v|
        expiry = v[:expiry] || v['expiry']
        DateTime.strptime(expiry.to_s, '%s') < Time.now
      end
    end
  end
end
