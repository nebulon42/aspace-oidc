# frozen_string_literal: true

ArchivesSpace::Application.routes.draw do
  scope AppConfig[:frontend_proxy_prefix] do
    # OMNIAUTH GENERATED ROUTES:
    # OMNIAUTH:      /auth/:provider

    if AppConfig[:oidc_definitions]
      AppConfig[:oidc_definitions].each do |oidc_definition|
        get  "/auth/#{oidc_definition[:config][:name]}/callback", to: 'oidc#create'
        post "/auth/#{oidc_definition[:config][:name]}/callback", to: 'oidc#create'
      end
    end
    get  '/auth/failure', to: 'oidc#failure'
  end
end
