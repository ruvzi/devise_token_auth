namespace :devise_token_auth do
  desc 'Authentications refactor'
  task authentications_refactor: :environment do
    Authentication.where(token: nil).where.not(provider: :email).find_each do |authentication|
      token = authentication.data.credentials.token
      expiry = authentication.data.credentials.expires_at
      expires_at = DateTime.strptime(expiry.to_s, '%s')
      authentication.update(token: token, expiry: expiry, expires_at: expires_at)
    end
  end
end

