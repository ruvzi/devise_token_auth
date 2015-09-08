module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_filter :assert_is_devise_resource!, :only => [:validate_token]
    before_filter :set_user_by_token, :only => [:validate_token]

    def validate_token
      # @resource will have been set by set_user_token concern
      if @authentication
        yield if block_given?
        render json: {
          success: true,
          data: @authentication.token_validation_response
        }
      else
        render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.token_validations.invalid")]
        }, status: 401
      end
    end
  end
end
