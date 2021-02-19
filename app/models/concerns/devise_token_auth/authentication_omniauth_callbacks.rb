# frozen_string_literal: true

module DeviseTokenAuth::AuthenticationOmniauthCallbacks
  extend ActiveSupport::Concern

  included do
    validates :email, presence: true,if: :email_provider?
    validates :email, devise_token_auth_email: true, allow_nil: true, allow_blank: true, if: :email_provider?
    validates_presence_of :uid, unless: :email_provider?

    # only validate unique emails among email registration users
    validates :email, uniqueness: { case_sensitive: false, scope: :provider }, on: :create, if: :email_provider?

    # keep uid in sync with email
    before_save :sync_uid
    before_create :sync_uid
  end

  protected

  def email_provider?
    provider == 'email'
  end

  def sync_uid
    if devise_modules.include?(:confirmable) && !@bypass_confirmation_postpone
      return if postpone_email_change?
    end

    new_uid = self.user&.email
    self.uid = new_uid if new_uid.present? email_provider?
  end
end
