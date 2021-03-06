module DeviseTokenAuth
  class RegistrationsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, :only => [:destroy, :update]
    before_action :validate_sign_up_params, :only => :create
    before_action :validate_account_update_params, :only => :update
    skip_after_action :update_auth_header, :only => [:create, :destroy]

    api! 'registrations.create.title'
    param :email, String, desc: 'registrations.create.params.email', required: true
    param :password, String, desc: 'registrations.create.params.password', required: true
    param :recaptcha, String, desc: 'registrations.create.params.recaptcha', required: true
    def create
      @resource = resource_class.new(sign_up_params)

      # honor devise configuration for case_insensitive_keys
      @resource.email =
        if resource_class.case_insensitive_keys.include?(:email)
          sign_up_params[:email]&.downcase
        else
          sign_up_params[:email]
        end

      # give redirect value from params priority
      @redirect_url = params[:confirm_success_url]

      # fall back to default value if provided
      @redirect_url ||= DeviseTokenAuth.default_confirm_success_url

      unless recaptcha_valid?(params['recaptcha'])
        return render json: {
          status: 'error',
          data: {
              errors: [I18n.t("devise_token_auth.registrations.not_verify_captcha")]
          },
          errors: [I18n.t("devise_token_auth.registrations.not_verify_captcha")]
        }, status: 403
      end

      # success redirect url is required
      if resource_class.devise_modules.include?(:confirmable) && !@redirect_url
        return render_create_error_missing_confirm_success_url
      end

      # if whitelist is set, validate redirect_url against whitelist
      if DeviseTokenAuth.redirect_whitelist
        unless DeviseTokenAuth.redirect_whitelist.include?(@redirect_url)
          return render_create_error_redirect_url_not_allowed
        end
      end

      begin
        # override email confirmation, must be sent manually from ctrl
        resource_class.set_callback('create', :after, :send_on_create_confirmation_instructions)
        resource_class.skip_callback('create', :after, :send_on_create_confirmation_instructions)
        if @resource.save
          @authentication = @resource.authentication(auth_domain)
          yield @resource if block_given?

          if @resource.active_for_authentication?
            # email auth has been bypassed, authenticate user
            @client_id = SecureRandom.urlsafe_base64(nil, false)
            @token     = SecureRandom.urlsafe_base64(nil, false)


            @authentication.tokens[@client_id] = {
              token: BCrypt::Password.create(@token),
              expiry: (Time.now + DeviseTokenAuth.token_lifespan).to_i
            }

            @authentication.save!
            @resource.add_profile!

            update_auth_header
          end
          unless @resource.confirmed?
            opts = {
              client_config: params[:config_name],
              redirect_url: @redirect_url,
              from: auth_domain&.devise_sender.presence || Devise.mailer_sender,
              domain_id: auth_domain&.id
            }
            mail_subject = auth_domain&.devise_confirmation_subject
            opts[:subject] = mail_subject if mail_subject
            @resource.send_confirmation_instructions(opts)
          end

          render_create_success
        else
          clean_up_passwords @resource
          render_create_error
        end
      rescue ActiveRecord::RecordNotUnique
        clean_up_passwords @resource
        render_create_error_email_already_exists
      end
    end

    # param :user, Hash,  desc: 'New user attributes', required: true do
    #   param :current_password, String, desc: 'User current password', required: true
    #   param :password, String, desc: 'User password', required: true
    #   param :password_confirmation, String, desc: 'User password confirmation', required: true
    # end

    def update
      if @resource
        @resource.skip_confirmation! if can?(:update_without_password, @resource)
        if @resource.send(resource_update_method, account_update_params)
          yield @resource if block_given?
          render_update_success
        else
          render_update_error
        end
      else
        render_update_error_user_not_found
      end
    end

    def destroy
      if @resource
        @resource.destroy
        yield @resource if block_given?

        render_destroy_success
      else
        render_destroy_error
      end
    end

    def sign_up_params
      params.permit(*params_for_resource(:sign_up))
    end

    def account_update_params
      params.permit(*params_for_resource(:account_update))
    end
    protected

    def render_create_error_missing_confirm_success_url
      render json: {
          status: 'error',
          data:   resource_data,
          errors: [I18n.t("devise_token_auth.registrations.missing_confirm_success_url")]
      }, status: 422
    end

    def render_create_error_redirect_url_not_allowed
      render json: {
          status: 'error',
          data:   resource_data,
          errors: [I18n.t("devise_token_auth.registrations.redirect_url_not_allowed", redirect_url: @redirect_url)]
      }, status: 422
    end

    def render_create_success
      render json: {
          status: 'success',
          data:   resource_data(resource_json: @authentication.decorate.user_response)
      }
    end

    def render_create_error
      render json: {
          status: 'error',
          data:   resource_data,
          errors: resource_errors
      }, status: 422
    end

    def render_create_error_email_already_exists
      render json: {
          status: 'error',
          data:   resource_data,
          errors: [I18n.t("devise_token_auth.registrations.email_already_exists", email: @resource.email)]
      }, status: 422
    end

    def render_update_success
      render json: {
          status: 'success',
          data:   resource_data
      }
    end

    def render_update_error
      render json: {
          status: 'error',
          errors: resource_errors
      }, status: 422
    end

    def render_update_error_user_not_found
      render json: {
          status: 'error',
          errors: [I18n.t("devise_token_auth.registrations.user_not_found")]
      }, status: 404
    end

    def render_destroy_success
      render json: {
          status: 'success',
          message: I18n.t("devise_token_auth.registrations.account_with_uid_destroyed", uid: @authentication.uid)
      }
    end

    def render_destroy_error
      render json: {
          status: 'error',
          errors: [I18n.t("devise_token_auth.registrations.account_to_destroy_not_found")]
      }, status: 404
    end

    private

    def resource_update_method
      if account_update_params.has_key?(:password) && can?(:update_without_password, @resource)
        'update_without_password'
      elsif DeviseTokenAuth.check_current_password_before_update == :attributes
        'update_with_password'
      elsif DeviseTokenAuth.check_current_password_before_update == :password and account_update_params.has_key?(:password)
        'update_with_password'
      elsif account_update_params.has_key?(:current_password)
        'update_with_password'
      else
        'update_attributes'
      end
    end

    def validate_sign_up_params
      validate_post_data sign_up_params, I18n.t("errors.validate_sign_up_params")
    end

    def validate_account_update_params
      validate_post_data account_update_params, I18n.t("errors.validate_account_update_params")
    end

    def validate_post_data which, message
      render json: {
         status: 'error',
         errors: [message]
      }, status: :unprocessable_entity if which.empty?
    end
  end
end
