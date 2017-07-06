class OmniauthCallbackJob < Struct.new(:record_class, :record_id, :authentication_id)
  def perform
    begin
      record = record_class.find(record_id)

      record.omniauth_success_callback!(record.authentications.find(authentication_id))
    rescue
    end
  end
end