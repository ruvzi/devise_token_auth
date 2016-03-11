module DeviseTokenAuth
  class PasswordsController < DeviseTokenAuth::ApplicationController
    before_filter :set_user_by_token, :only => [:update]
    skip_after_filter :update_auth_header, :only => [:create, :edit]

    # this action is responsible for generating password reset tokens and
    # sending emails
    def create
      unless resource_params[:email]
        return render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.passwords.missing_email")]
        }, status: 401
      end

      # give redirect value from params priority
      redirect_url = params[:redirect_url]

      # fall back to default value if provided
      redirect_url ||= DeviseTokenAuth.default_password_reset_url

      unless redirect_url
        return render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.passwords.missing_redirect_url")]
        }, status: 401
      end

      # if whitelist is set, validate redirect_url against whitelist
      if DeviseTokenAuth.redirect_whitelist
        unless DeviseTokenAuth.redirect_whitelist.include?(redirect_url)
          return render json: {
            status: 'error',
            data: @resource.decorate.user_response,
            errors: [I18n.t("devise_token_auth.passwords.not_allowed_redirect_url", redirect_url: redirect_url)]
          }, status: 403
        end
      end

      # honor devise configuration for case_insensitive_keys
      if resource_class.case_insensitive_keys.include?(:email)
        email = resource_params[:email].downcase
      else
        email = resource_params[:email]
      end

      q = "authentications.uid = ? AND authentications.provider='email'"

      # fix for mysql default case insensitivity
      if ActiveRecord::Base.connection.adapter_name.downcase.starts_with? 'mysql'
        q = 'BINARY' + q
      end

      @resource = resource_class.joins(:authentications).where(q, email).first

      errors = nil
      error_status = 400

      if @resource
        @authentication = @resource.authentications.uid(email).first
        yield if block_given?
        @resource.send_reset_password_instructions({
          email: email,
          provider: 'email',
          redirect_url: redirect_url,
          client_config: params[:config_name]
        })

        if @resource.errors.empty?
          render json: {
            success: true,
            message: I18n.t("devise_token_auth.passwords.sended", email: email)
          }
        else
          errors = @resource.errors
        end
      else
        errors = [I18n.t("devise_token_auth.passwords.user_not_found", email: email)]
        error_status = 404
      end

      if errors
        render json: {
          success: false,
          errors: errors,
        }, status: error_status
      end
    end


    # this is where users arrive after visiting the password reset confirmation link
    def edit
      @resource = resource_class.reset_password_by_token({
        reset_password_token: resource_params[:reset_password_token]
      })
      @authentication = @resource.authentication

      if @resource && @authentication && @authentication.persisted?
        client_id  = SecureRandom.urlsafe_base64(nil, false)
        token      = SecureRandom.urlsafe_base64(nil, false)
        token_hash = BCrypt::Password.create(token)
        expiry     = (Time.now + DeviseTokenAuth.token_lifespan).to_i

        @authentication.tokens[client_id] = {
          token:  token_hash,
          expiry: expiry
        }

        # ensure that user is confirmed
        @resource.skip_confirmation! if @resource.devise_modules.include?(:confirmable) && !@resource.confirmed_at

        @resource.allow_password_change = true

        @authentication.save!
        @resource.save!
        yield if block_given?

        redirect_to(@authentication.build_auth_url(params[:redirect_url], {
          token:          token,
          client_id:      client_id,
          reset_password: true,
          config:         params[:config]
        }))
      else
        render json: {
          success: false
        }, status: 404
      end
    end

    def update
      # make sure user is authorized
      unless @authentication
        return render json: {
          success: false,
          errors: ['Unauthorized']
        }, status: 401
      end

      # make sure account doesn't use oauth2 provider
      unless @authentication.provider.eql?('email')
        return render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.passwords.password_not_required", provider: @authentication.provider.humanize)]
        }, status: 422
      end

      # ensure that password params were sent
      unless password_resource_params[:password] and password_resource_params[:password_confirmation]
        return render json: {
          success: false,
          errors: [I18n.t("devise_token_auth.passwords.missing_passwords")]
        }, status: 422
      end

      if @resource.send(resource_update_method, password_resource_params)
        @resource.allow_password_change = false
        yield if block_given?
        return render json: {
          success: true,
          data: {
            user: @resource.decorate.user_response,
            message: I18n.t("devise_token_auth.passwords.successfully_updated")
          }
        }
      else
        return render json: {
          success: false,
          errors: @resource.errors.to_hash.merge(full_messages: @resource.errors.full_messages)
        }, status: 422
      end
    end

    protected

    def resource_update_method
      if DeviseTokenAuth.check_current_password_before_update == false or @resource.allow_password_change == true
        'update_attributes'
      else
        'update_with_password'
      end
    end

    private

    def resource_params
      params.permit(:email, :password, :password_confirmation, :current_password, :reset_password_token)
    end

    def password_resource_params
      params.permit(devise_parameter_sanitizer.for(:account_update))
    end
  end
end
