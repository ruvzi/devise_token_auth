module DeviseTokenAuth::Concerns::SetUserByToken
  extend ActiveSupport::Concern
  include DeviseTokenAuth::Controllers::Helpers

  included do
    before_action :set_request_start
    after_action :update_auth_header
  end

  protected

  # keep track of request duration
  def set_request_start
    @request_started_at = Time.now
    @used_auth_by_token = true
  end

  # user auth
  def set_user_by_token(mapping=nil)
    # determine target authentication class
    rc = resource_class(mapping)

    # no default user defined
    return unless rc

    # gets the headers names, which was set in the initialize file
    uid_name = DeviseTokenAuth.headers_names[:'uid']
    access_token_name = DeviseTokenAuth.headers_names[:'access-token']
    client_name = DeviseTokenAuth.headers_names[:'client']

    # parse header for values necessary for authentication
    uid        = request.headers[uid_name] || params[uid_name]
    @token     ||= request.headers[access_token_name] || params[access_token_name]
    @client_id ||= request.headers[client_name] || params[client_name]

    # client_id isn't required, set to 'default' if absent
    @client_id ||= 'default'

    # check for an existing user, authenticated via warden/devise
    if DeviseTokenAuth.enable_standard_devise_support
      devise_warden_user = warden.user(rc.to_s.underscore.to_sym)
  
      if devise_warden_user && devise_warden_user.tokens[@client_id].nil?
        @used_auth_by_token = false
        @resource = devise_warden_user
        @authentication = uid && @resource.authentications.uid(uid).first || @resource.authentications.first
        @authentication.create_new_auth_token
      end
    end

    # user has already been found and authenticated
    return @resource if @resource and @resource.class == rc

    # ensure we clear the client_id
    unless @token
      @client_id = nil
      return
    end

    return false unless @token

    # mitigate timing attacks by finding by uid instead of auth token
    authentication = uid && Authentication.uid(uid).first
    user = authentication.try(:user)

    if user && authentication.valid_token?(@token, @client_id)
      bypass_sign_in(user, scope: :user)
      @authentication = authentication
      @resource = user
    else
      # zero all values previously set values
      @client_id = nil
      @authentication = nil
      @resource = nil
    end
  end


  def update_auth_header
    # cannot save object if model has invalid params
    return unless @resource and @resource.valid? and @client_id

    # Generate new client_id with existing authentication
    @client_id = nil unless @used_auth_by_token

    if @used_auth_by_token && !DeviseTokenAuth.change_headers_on_each_request
      return if @resource.reload.tokens[@client_id].nil?
      auth_header = @authentication.build_auth_header(@token, @client_id)
      # update the response header
      response.headers.merge!(auth_header)

    else
      # Lock the user record during any auth_header updates to ensure
      # we don't have write contention from multiple threads
      @resource.with_lock do
  
        return if @used_auth_by_token && @resource.tokens[@client_id].nil?

        # determine batch request status after request processing, in case
        # another processes has updated it during that processing
        @is_batch_request = is_batch_request?(@resource, @client_id)
        # extend expiration of batch buffer to account for the duration of
        # this request
        if @is_batch_request
          auth_header = @authentication.extend_batch_buffer(@token, @client_id)
  
          # Do not return token for batch requests to avoid invalidated
          # tokens returned to the client in case of race conditions.
          # Use a blank string for the header to still be present and
          # being passed in a XHR response in case of
          # 304 Not Modified responses.
          auth_header[DeviseTokenAuth.headers_names[:"access-token"]] = ' '
          auth_header[DeviseTokenAuth.headers_names[:"expiry"]] = ' '
  
          # update Authorization response header with new token
        else
          auth_header = @authentication.create_new_auth_token(@client_id)
        end
        # update the response header
        response.headers.merge!(auth_header)

      end # end lock
    end

    sign_out(@resource)

  end

  def resource_class(m=nil)
    if m
      mapping = Devise.mappings[m]
    else
      mapping = Devise.mappings[resource_name] || Devise.mappings.values.first
    end
    mapping.to
  end

  def recaptcha_valid?(code)
    return true if code.nil?
    response = Net::HTTP.get_response(URI.parse("https://www.google.com/recaptcha/api/siteverify?secret=#{ENV['recaptcha_private_key']}&response=#{code}&remoteip=#{request.remote_ip}"))
    JSON.parse(response.body)['success']
  end

  private
  def is_batch_request?(user, client_id)
    not params[:unbatch] and
    user.tokens[client_id] and
    user.tokens[client_id]['updated_at'] and
    Time.parse(user.tokens[client_id]['updated_at']) > @request_started_at - DeviseTokenAuth.batch_request_buffer_throttle
  end
end
