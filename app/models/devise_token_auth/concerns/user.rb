module DeviseTokenAuth::Concerns::User
  extend ActiveSupport::Concern

  def self.tokens_match?(token_hash, token)
    @token_equality_cache ||= {}

    key = "#{token_hash}/#{token}"
    result = @token_equality_cache[key] ||= (::BCrypt::Password.new(token_hash) == token)
    if @token_equality_cache.size > 10000
      @token_equality_cache = {}
    end
    result
  end

  included do
    # Hack to check if devise is already enabled
    if self.method_defined?(:devise_modules)
      self.devise_modules.delete(:omniauthable)
    else
      devise :database_authenticatable, :registerable,
             :recoverable, :trackable, :validatable, :confirmable
    end

    has_many :authentications, dependent: :destroy, autosave: true

    after_create :add_email_authentication

    # allows user to change password without current_password
    attr_writer :allow_password_change
    def allow_password_change
      @allow_password_change || false
    end

    def authentication(domain)
	    authentications.domained(domain).provider('email').first_or_create
    end

    def tokens
	    authentication&.tokens
    end

    # override devise method to include additional info as opts hash
    def send_confirmation_instructions(opts = {})
      unless @raw_confirmation_token
        generate_confirmation_token!
      end

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      if pending_reconfirmation?
        opts[:to] = unconfirmed_email
      end

      send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
    end

    # override devise method to include additional info as opts hash
    def send_reset_password_instructions( opts = {})
      token = set_reset_password_token

      # fall back to "default" config name
      opts[:client_config] ||= 'default'

      send_devise_notification(:reset_password_instructions, token, opts)

      token
    end
  end

  # this must be done from the controller so that additional params
  # can be passed on from the client
  def send_confirmation_notification?
    false
  end

  def confirmed?
    self.devise_modules.exclude?(:confirmable) || super
  end

  def no_authentications?
    authentications.count.zero?
  end

  def extra_response
    {}
  end

  protected
  def authentication_email
    self.authentication.update(uid: self.email)
  end

  def add_email_authentication
    self.create_authentication if self.authentication.blank?
  end
end
