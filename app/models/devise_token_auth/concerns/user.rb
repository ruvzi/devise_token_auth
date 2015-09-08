module DeviseTokenAuth::Concerns::User
  extend ActiveSupport::Concern

  included do
    # Hack to check if devise is already enabled
    if self.method_defined?(:devise_modules)
      self.devise_modules.delete(:omniauthable)
    else
      devise :database_authenticatable, :registerable,
             :recoverable, :trackable, :validatable, :confirmable
    end

    has_many :authentications, dependent: :destroy, autosave: true
    has_one  :authentication

    delegate :tokens, to: :authentication

    before_save :build_authentication, if: :no_authentications?
    # don't use default devise email validation
    def email_required?
      false
    end

    def email_changed?
      false
    end

    # override devise method to include additional info as opts hash
    def send_confirmation_instructions(opts=nil)
      unless @raw_confirmation_token
        generate_confirmation_token!
      end

      opts ||= {}

      # fall back to "default" config name
      opts[:client_config] ||= "default"

      if pending_reconfirmation?
        opts[:to] = unconfirmed_email
      end

      send_devise_notification(:confirmation_instructions, @raw_confirmation_token, opts)
    end

    # override devise method to include additional info as opts hash
    def send_reset_password_instructions(opts=nil)
      token = set_reset_password_token

      opts ||= {}

      # fall back to "default" config name
      opts[:client_config] ||= "default"

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
end
