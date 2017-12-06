class Mang < ApplicationRecord
  include DeviseTokenAuth::Concerns::User
end
