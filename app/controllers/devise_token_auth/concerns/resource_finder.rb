# frozen_string_literal: true

module DeviseTokenAuth::Concerns::ResourceFinder
  extend ActiveSupport::Concern
  include DeviseTokenAuth::Controllers::Helpers

  def get_case_insensitive_field_from_resource_params(field)
    # honor Devise configuration for case_insensitive keys
    q_value = resource_params[field.to_sym]

    if resource_class.case_insensitive_keys.include?(field.to_sym)
      q_value.downcase!
    end

    if resource_class.strip_whitespace_keys.include?(field.to_sym)
      q_value.strip!
    end

    q_value
  end

  def find_resource(field, value)
    authentication_q = "authentications.uid = ? AND authentications.provider='email'"

    @resource = resource_class.joins(:authentications).where(authentication_q, value).first
    @resource ||= resource_class.find_by(field => value)
  end

  def resource_class(m = nil)
    mapping = if m
                Devise.mappings[m]
              else
                Devise.mappings[resource_name] || Devise.mappings.values.first
              end

    mapping.to
  end
end
