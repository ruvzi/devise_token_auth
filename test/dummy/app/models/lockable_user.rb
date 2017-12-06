class LockableUser < ApplicationRecord
  # Include default devise modules.
  devise :database_authenticatable, :registerable, :lockable
  include DeviseTokenAuth::Concerns::User
end
