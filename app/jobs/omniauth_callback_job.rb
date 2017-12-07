class OmniauthCallbackJob < ApplicationJob
  queue_as :default

  def perform(record_class, record_id, authentication_id)
    begin
      record = record_class.constantize.find(record_id)

      record.omniauth_success_callback!(record.authentications.find(authentication_id))
    rescue
    end
  end
end