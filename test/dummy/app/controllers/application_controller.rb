class ApplicationController < ActionController::Base
  include DeviseTokenAuth::Concerns::SetUserByToken

  before_action :configure_permitted_parameters, if: :devise_controller?

  protected

  def configure_permitted_parameters
    devise_parameter_sanitizer.sanitize(:sign_up) << :operating_thetan
    devise_parameter_sanitizer.sanitize(:sign_up) << :favorite_color
    devise_parameter_sanitizer.sanitize(:account_update) << :current_password
    devise_parameter_sanitizer.sanitize(:account_update) += SETTS['account_update_params'] || []
  end
end
