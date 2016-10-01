module DeviseTokenAuth
  class ConfirmationsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, only: [:new]

    def new
      @resource.send_confirmation_instructions
      render json: {success: successfully_sent?(@resource)}
    end

    def create
      #TODO add send by find email
      @resource = resource_class.send_confirmation_instructions(resource_params)
    end

    def show
      @resource = resource_class.confirm_by_token(params[:confirmation_token])
      @authentication = @resource.authentication || @resource.create_authentication
      if @resource && @authentication && @authentication.persisted?
        # create client id
        client_id  = SecureRandom.urlsafe_base64(nil, false)
        token      = SecureRandom.urlsafe_base64(nil, false)
        token_hash = BCrypt::Password.create(token)
        expiry     = (Time.now + DeviseTokenAuth.token_lifespan).to_i

        @authentication.tokens[client_id] = {
          token:  token_hash,
          expiry: expiry
        }

        @authentication.save!
        @resource.save!

        yield if block_given?

        redirect_to(@authentication.build_auth_url(params[:redirect_url].presence || root_url, {
          token:                        token,
          client_id:                    client_id,
          account_confirmation_success: true,
          config:                       params[:config]
        }))
      else
        raise ActionController::RoutingError.new('Not Found')
      end
    end
  end
end
