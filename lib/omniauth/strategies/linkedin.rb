require 'omniauth-oauth2'

module OmniAuth
  module Strategies

    class LinkedIn < OmniAuth::Strategies::OAuth2

      option :name, 'linkedin'

      option :client_options, {
        site:          'https://api.linkedin.com',
        authorize_url: 'https://www.linkedin.com/uas/oauth2/authorization?response_type=code',
        token_url:     'https://www.linkedin.com/uas/oauth2/accessToken'
      }

      option :scope, 'r_basicprofile r_emailaddress'

      option :fields, [
        'id',
        'email-address',
        'first-name',
        'last-name',
        'headline',
        'location',
        'industry',
        'picture-url',
        'public-profile-url'
      ]

      uid { raw_info['id'].to_s }

      info do
        {
          name:        user_name,
          email:       raw_info['emailAddress'],
          first_name:  raw_info['firstName'],
          last_name:   raw_info['lastName'],
          location:    raw_info['location'],
          description: raw_info['headline'],
          image:       raw_info['pictureUrl'],
          urls:        { 'public_profile' => raw_info['publicProfileUrl'] }
        }
      end

      extra do
        { 'raw_info' => raw_info }
      end

      alias :oauth2_access_token :access_token

      def args
        binding.pry
      end

      def access_token
        ::OAuth2::AccessToken.new(client, oauth2_access_token.token, {
          mode: :query,
          param_name: 'oauth2_access_token',
          expires_in: oauth2_access_token.expires_in,
          expires_at: oauth2_access_token.expires_at
        })
      end

      def raw_info
        @raw_info ||= access_token.get("/v1/people/~:(#{option_fields})?format=json").parsed
      end

      private

      def option_fields
        fields = options.fields
        fields.map! { |f| f == "picture-url" ? "picture-url;secure=true" : f } if !!options[:secure_image_url]
        fields.join(',')
      end

      def user_name
        name = "#{raw_info['firstName']} #{raw_info['lastName']}".strip
        name.empty? ? nil : name
      end
    end

  end
end

OmniAuth.config.add_camelization 'linkedin', 'LinkedIn'
