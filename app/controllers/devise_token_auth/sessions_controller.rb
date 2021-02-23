# see http://www.emilsoman.com/blog/2013/05/18/building-a-tested/
module DeviseTokenAuth
  class SessionsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, only: [:destroy]
    after_action :reset_session, only: [:destroy]

    def new
      render_new_error
    end

    def create
      # Check
      field = (resource_params.keys.map(&:to_sym) & resource_class.authentication_keys).first

      @resource = nil
      q_value = nil
      if field
        q_value = get_case_insensitive_field_from_resource_params(field)

        @resource = find_resource(field, q_value)
        @authentication = @resource.authentication(auth_domain) if @resource
      end

      if @resource && !@resource.blocked? && valid_params?(field, q_value) && (!@resource.respond_to?(:active_for_authentication?) || @resource&.active_for_authentication?)
        valid_password = @resource&.valid_password?(resource_params[:password])

        if (@resource.respond_to?(:valid_for_authentication?) && !@resource&.valid_for_authentication? { valid_password }) || !valid_password
          return render_create_error_bad_credentials
        end

        @token = @authentication.create_token
        @authentication.domain_id = auth_domain&.id
        @authentication.save


        # sign_in(:user, @resource, store: true, forse: true) #OLD
        sign_in(:user, @resource, store: false, bypass: false)

        yield @resource if block_given?

        render_create_success

      elsif @resource&.blocked?
        render_create_error_blocked
      elsif @resource && !(!@resource.respond_to?(:active_for_authentication?) || @resource&.active_for_authentication?)
        if @resource.respond_to?(:locked_at) && @resource&.locked_at
          render_create_error_account_locked
        else
          render_create_error_not_confirmed
        end
      else
        render_create_error_bad_credentials
      end
    end

    def destroy
      # remove auth instance variables so that after_action does not run
      user = @resource ? remove_instance_variable(:@resource) : nil
      authentication = @authentication ? remove_instance_variable(:@authentication) : nil
      client = @token.client
      @token.clear!

      if user && authentication && client && authentication.tokens[client]
        authentication.tokens.delete(client)
        authentication.save!

        yield user if block_given?

        render_destroy_success
      else
        render_destroy_error
      end
    end

    def login_as
      user = User.find_by(id: params[:user_id])
      if user && ((is_admin = session[:admin_id].eql?(user.id)) || can?(:login_as, user))
        if is_admin
          session.delete(:admin_id)
        else
          admin_id = current_user.id
        end
        @resource = user
        @authentication = @resource.authentication(auth_domain)
        @token = @authentication.create_token
        @authentication.save

        bypass_sign_in(@resource, scope: :user)
        session[:admin_id] = admin_id

        render_create_success
      else
        render_error(401, 'unauthorized')
      end
    end

    protected

    def valid_params?(key, val)
      resource_params[:password] && key && val
    end

    def get_auth_params
      auth_key = nil
      auth_val = nil

      # iterate thru allowed auth keys, use first found
      resource_class.authentication_keys.each do |k|
        if resource_params[k]
          auth_val = resource_params[k]
          auth_key = k
          break
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(auth_key)
        auth_val.downcase!
      end

      { key: auth_key, val: auth_val }
    end

    def render_new_error
      render_error(405, I18n.t('devise_token_auth.sessions.not_supported'))
    end

    def render_create_success
      render json: { data: resource_data(resource_json: @authentication.decorate.user_response) }, status: 200
    end

    def render_create_error_blocked
      render_error(401, I18n.t('devise_token_auth.sessions.user_blocked', email: @resource.email))
    end

    def render_create_error_not_confirmed
      render_error(401, I18n.t('devise_token_auth.sessions.not_confirmed', email: @resource.email))
    end

    def render_create_error_account_locked
      render_error(401, I18n.t('devise.mailer.unlock_instructions.account_lock_msg'))
    end

    def render_create_error_bad_credentials
      render_error(401, I18n.t('devise_token_auth.sessions.bad_credentials'))
    end

    def render_destroy_success
      render json: { success: true }, status: 200
    end

    def render_destroy_error
      render_error(404, I18n.t('devise_token_auth.sessions.user_not_found'))
    end

    private

    def resource_params
      params.permit(*params_for_resource(:sign_in))
    end
  end
end
