class AuthenticationDecorator < Draper::Decorator
  delegate_all

  def full_name
    [first_name, last_name].compact.join(' ').presence || info['name']
  end

  def first_name
    info['first_name'] || info_name.first
  end

  def last_name
    info['last_name'] || info_name.last
  end

  def info_name
    info['name'].split(' ').join(' ').to_s[/([\S]+) ([\S]+)/i]
    [$1, $2]
  end

  def auth_url
    case provider
      when 'facebook'
        "http://facebook.com/#{uid}"
    end
  end

  def url
    case provider
      when 'instagram'
        "http://instagram.com/#{info['nickname']}"
      when 'youtube'
        auth['extra']['user_hash']['link'].first['href']
      when 'tumblr'
        info['blogs'].first['url']
      else
        (urls = info && info['urls']).present? ? (urls[provider.capitalize] || urls[provider]) : auth_url
    end
  end

  def image_uri
    image_uri = info['image'].presence || info['avatar'].presence || raw_info['pic_1'].presence
    if image_uri.present?
      image_uri = image_uri.gsub('http://','https://') + '?type=large' if provider.eql?('facebook')
      image_uri = image_uri.gsub('photoType=4','photoType=3') if provider.eql?('odnoklassniki')
      image_uri = image_uri.gsub('?sz=50','') if provider.eql?('google_oauth2')
    end
    image_uri
  end

  def avatar
    h.image_tag(image_uri, class: 'img-responsive')
  end

  def gender
    if raw_info.present?
      if raw_info['gender'].present?
        raw_info['gender'].eql?('female')
      elsif raw_info['sex'].present?
        raw_info['sex'].eql?(1)
      end
    end
  end

  def city_id
    city.try(:id)
  end

  def city
    city_name = case provider
                  when 'vkontakte'
                    info['location'].split(', ').last
                  when 'odnoklassniki'
                    raw_info['location'].city
                  when 'facebook'
                    raw_info['location'].try(:name)
                  when 'twitter'
                    raw_info['location']
                  else
                    info['location']
                end
    if city_name.present?
      country.present? ? country.cities.find_by_name(city_name) :
          City.where('name = ? or slug like ?', city_name, "#{city_name.downcase}%").first
    end
  end

  def country_id
    country.try(:id)
  end

  def country
    country_name = case provider
                     when 'vkontakte'
                       info['location'].split(', ').first
                     when 'odnoklassniki'
                       raw_info['location']['countryName']
                     else
                       nil
                   end
    Country.find_by_name(country_name) if country_name.present?
  end

  def provider
    auth['provider']
  end

  def user_response
    response = {
      id: object.id,
      user_id: object.user_id,
      uid: object.uid,
      provider: object.provider,
      adult_show: object.user.client.settings(:privacy).adult_show
    }
    response.merge!(object.user.decorate.extra_response)
    response
  end

  protected
  def auth
    object.data
  end

  def info
    auth['info']
  end

  def raw_info
    auth['extra'].try([],'raw_info') || {}
  end
end
