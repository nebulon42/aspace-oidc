# frozen_string_literal: true

require 'log'
require_relative 'lib/as_oidc_util'

if Object.const_defined?('Rails')
  require_relative 'lib/omniauth/rails_csrf_protection/railtie'
end

oidc_definitions = AppConfig[:authentication_sources].find_all do |as|
  as[:model] == 'ASOidc'
end
unless oidc_definitions.any?
  raise 'The ArchivesSpace OIDC plugin was enabled but no definitions for OIDC providers were provided.'
end

# also used for ui [refactor]
AppConfig[:oidc_definitions] = oidc_definitions
ArchivesSpace::Application.extend_aspace_routes(
  File.join(File.dirname(__FILE__), 'routes.rb')
)
require 'omniauth'

Rails.application.config.middleware.use OmniAuth::Builder do
  oidc_definitions.each do |oidc_definition|
    config = oidc_definition[:config]
    provider :openid_connect, config
    Log.info("Aspace OIDC: registered OIDC provider #{config[:name]}")
  end
end
