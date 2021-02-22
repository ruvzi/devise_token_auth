# frozen_string_literal: true

module DeviseTokenAuth::AuthenticationOmniauthCallbacks
  extend ActiveSupport::Concern

  included do
    validates_presence_of :uid, unless: :email_provider?
    # keep uid in sync with email
    before_save :sync_uid
    before_create :sync_uid
  end

  protected

  def email_provider?
    provider == 'email'
  end

  def sync_uid
    return if user.not_sync_email?


    new_uid = self.user&.email
    self.uid = new_uid if new_uid.present? && email_provider?
  end
end
