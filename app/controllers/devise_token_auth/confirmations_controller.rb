module DeviseTokenAuth
  class ConfirmationsController < DeviseTokenAuth::ApplicationController
    before_action :set_user_by_token, only: [:new]

    def new
      opts = { from: sender_mail }
      opts[:subject] = mail_subject if mail_subject
      @resource.send_confirmation_instructions(opts)
      render json: { success: successfully_sent?(@resource) }
    end

    def create
      #TODO add send by find email
      opts = resource_params.merge!(from: sender_mail)
      opts[:subject] = mail_subject if mail_subject
      @resource = resource_class.send_confirmation_instructions(opts)
    end

    def show
      @resource = resource_class.confirm_by_token(params[:confirmation_token])
      @authentication = @resource.authentication(auth_domain)
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

        yield @resource if block_given?

        redirect_to(@authentication.build_auth_url(params[:redirect_url].presence || root_url, {
          token:                        token,
          client_id:                    client_id,
          account_confirmation_success: true,
          config:                       params[:config]
        }))
      else
        redirect_to root_url, alert: 'Not Found'
      end
    end

    protected

    def sender_mail
      auth_domain&.devise_sender.presence || Devise.mailer_sender
    end

    def mail_subject
      auth_domain&.devise_confirmation_subject
    end
  end
end
