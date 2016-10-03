module DeviseTokenAuth
  class TokenValidationsController < DeviseTokenAuth::ApplicationController
    skip_before_action :assert_is_devise_resource!, :only => [:validate_token]
    before_action :set_user_by_token, :only => [:validate_token]

    resource_description do
      short 'token_validations.short'
      api_base_url ''
    end
    api :GET, '/auth/validate_token', 'token_validations.validate_token'

    def validate_token
      # @resource will have been set by set_user_token concern
      if @authentication
        yield @authentication if block_given?
        render_validate_token_success
      else
        render_validate_token_error
      end
    end

    protected

    def render_validate_token_success
      render json: {
          success: true,
          data: resource_data(resource_json: @authentication.decorate.user_response)
      }
    end

    def render_validate_token_error
      render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.token_validations.invalid")]
      }, status: 401
    end
  end
end
