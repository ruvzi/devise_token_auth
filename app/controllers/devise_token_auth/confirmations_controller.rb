module DeviseTokenAuth
  class ConfirmationsController < DeviseTokenAuth::ApplicationController
    def show
      @resource = resource_class.confirm_by_token(resource_params[:confirmation_token])
      @authentication = @resource.authentication(auth_domain)
      if @resource && @authentication && @authentication.persisted? && @resource.errors.empty?
        redirect_header_options = { account_confirmation_success: true }

        yield @resource if block_given?

        if signed_in?
          token = @authentication.create_token
          @authentication.save!
          @resource.save!

          redirect_headers = build_redirect_headers(token.token,
                                                    token.client,
                                                    redirect_header_options)

          redirect_to_link = @authentication.build_auth_url(redirect_url, redirect_headers)
        else
          redirect_to_link = DeviseTokenAuth::Url.generate(redirect_url, redirect_header_options)
        end

        redirect_to(redirect_to_link)
      else
        raise ActionController::RoutingError, 'Not Found'
      end
    end

    def create
      return render_create_error_missing_email if resource_params[:email].blank?

      @email = get_case_insensitive_field_from_resource_params(:email)
      @resource = find_resource(:email, @email)

      return render_not_found_error unless @resource

      #TODO: add send by current_user email
      opts = resource_params.merge!(from: sender_mail, redirect_url: redirect_url)
      opts[:subject] = mail_subject if mail_subject
      @resource.send_confirmation_instructions(opts)

      render_create_success
    end

    protected

    def render_create_error_missing_email
      render_error(401, I18n.t('devise_token_auth.confirmations.missing_email'))
    end

    def render_create_success
      render json: { success: true, message: I18n.t('devise_token_auth.confirmations.sended', email: @email) }
    end

    def render_not_found_error
      render_error(404, I18n.t('devise_token_auth.confirmations.user_not_found', email: @email))
    end

    private

    def sender_mail
      auth_domain&.devise_sender.presence || Devise.mailer_sender
    end

    def mail_subject
      auth_domain&.devise_confirmation_subject
    end

    def resource_params
      params.permit(:email, :confirmation_token, :config_name)
    end

    # give redirect value from params priority or fall back to default value if provided
    def redirect_url
      params.fetch(:redirect_url, DeviseTokenAuth.default_confirm_success_url)
    end
  end
end
