class EvilUser < ApplicationRecord
  include DeviseTokenAuth::Concerns::User
end
