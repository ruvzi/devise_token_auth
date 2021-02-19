module DeviseTokenAuth::User
  extend ActiveSupport::Concern

  def self.tokens_match?(token_hash, token)
    @token_equality_cache ||= {}

    key = "#{token_hash}/#{token}"
    result = @token_equality_cache[key] ||= DeviseTokenAuth::TokenFactory.token_hash_is_token?(token_hash, token)
    @token_equality_cache = {} if @token_equality_cache.size > 10000
    result
  end

  included do
    # Hack to check if devise is already enabled
    if method_defined?(:devise_modules)
      devise_modules.delete(:omniauthable)
    else
      devise :database_authenticatable, :registerable,
             :recoverable, :trackable, :validatable, :confirmable
    end

    include DeviseTokenAuth::ActiveRecordSupport

    has_many :authentications, dependent: :destroy, autosave: true
    has_one :active_authentication, -> { order(updated_at: :desc) }, class_name: 'Authentication'

    delegate :domain, to: :active_authentication, allow_nil: true

    # remove old tokens if password has changed
    before_save :remove_tokens_after_password_reset

    # don't use default devise email validation
    def email_required?; false; end
    def email_changed?; false; end
    def will_save_change_to_email?; false; end

    if DeviseTokenAuth.send_confirmation_email && devise_modules.include?(:confirmable)
      include DeviseTokenAuth::ConfirmableSupport
    end

    # allows user to change password without current_password
    attr_writer :allow_password_change
    def allow_password_change
      @allow_password_change || false
    end

    def authentication(domain = nil)
      authentications.domained(domain).provider('email').first_or_create
    end

    def tokens(domain = nil)
      authentication(domain)&.tokens.presence || {}
    end

    # override devise method to include additional info as opts hash
    def send_confirmation_instructions(opts = {})
      generate_confirmation_token! unless @raw_confirmation_token

      # fall back to "default" config name
      opts[:client_config] ||= 'default'
      opts[:to] = unconfirmed_email if pending_reconfirmation?
      opts[:redirect_url] ||= DeviseTokenAuth.default_confirm_success_url

      send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
    end

    # override devise method to include additional info as opts hash
    def send_reset_password_instructions(opts = {})
      token = set_reset_password_token

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      send_devise_notification(:reset_password_instructions, token, opts)
      token
    end

    # override devise method to include additional info as opts hash
    def send_unlock_instructions(opts = {})
      raw, enc = Devise.token_generator.generate(self.class, :unlock_token)
      self.unlock_token = enc
      save(validate: false)

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      send_devise_notification(:unlock_instructions, raw, opts)
      raw
    end
  end

  # this must be done from the controller so that additional params
  # can be passed on from the client
  def send_confirmation_notification?; false; end

  def confirmed?
    devise_modules.exclude?(:confirmable) || super
  end

  def no_authentications?
    authentications.count.zero?
  end

  def extra_response
    {}
  end

  private

  def authentication_email(domain)
    self.authentication(domain).update(uid: self.email)
  end

  def should_remove_tokens_after_password_reset?
    saved_change_to_attribute?(:encrypted_password) &&
      DeviseTokenAuth.remove_tokens_after_password_reset
  end

  def remove_tokens_after_password_reset
    return unless should_remove_tokens_after_password_reset?

    authentications.provider(:email).find_each do |authentication|
      authentication.send(:remove_tokens_after_user_password_reset)
    end
  end
end
