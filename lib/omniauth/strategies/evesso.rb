require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Evesso < OmniAuth::Strategies::OAuth2
      # Give your strategy a name.
      option :name, "evesso"

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        site: "https://login.eveonline.com",
        authorize_url: "https://login.eveonline.com/oauth/authorize"
      }

      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid do
       raw_info['CharacterID']
      end

      info do
        {
          character_id: raw_info['CharacterID'],
          name: raw_info['CharacterName'],
          token_type: raw_info['TokenType'],
          character_owner_hash: raw_info['CharacterOwnerHash'],
          expires_on: raw_info['ExpiresOn'],
          scopes: raw_info['Scopes']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.get('/oauth/verify').parsed
      end
    end
  end
end
