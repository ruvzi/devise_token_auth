class OnlyEmailUser < ApplicationRecord
  # Include default devise modules.
  devise :database_authenticatable, :registerable
  include DeviseTokenAuth::Concerns::User
end
