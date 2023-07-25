# frozen_string_literal: true

require 'log'

class OidcController < ApplicationController
  skip_before_action :unauthorised_access
  skip_before_action :verify_authenticity_token

  # IMPLEMENTS: /auth/:name/callback
  # Successful authentication populates the auth_hash with data
  # that is written to the system tmpdir. This is used to verify
  # the user for the backend and then deleted.
  def create
    pw      = "aspace-oidc-#{auth_hash[:provider]}-#{SecureRandom.uuid}"
    pw_path = File.join(Dir.tmpdir, pw)
    backend_session = nil
    oidc_config = nil
    if AppConfig[:oidc_definitions].respond_to?('each')
      AppConfig[:oidc_definitions].each do |oidc_definition, idx|
        if oidc_definition.key?(:config) && oidc_definition[:config].key?(:name)
          Log.debug("Aspace OIDC: Processing configuration for provider #{oidc_definition[:config][:name]}.")
          if oidc_definition[:config][:name] == auth_hash[:provider]
            oidc_config = oidc_definition
            Log.debug("Aspace OIDC: Found configuration for provider #{auth_hash[:provider]}.")
            break
          end
        else
          Log.warn("Aspace OIDC: Configuration ##{idx} is malformed.")
        end
      end
    else
      Log.error("Aspace OIDC: OIDC definitions are not set (correctly) in the application config.")
    end

    if oidc_config
      email = ASOidcUtil.get_email(auth_hash)
      if oidc_config.key?(:username_field)
        username = ASOidcUtil.get_field(auth_hash, oidc_config[:username_field])
        if username == nil
          Log.debug("Aspace OIDC: Was not able to retrieve username from token.")
        end
      else
        username = email
        # usernames cannot be email addresses (legacy) and will be downcased:
        # https://github.com/archivesspace/archivesspace/blob/master/backend/app/model/user.rb#L117-L121
        username = username.split('@').first.downcase
      end
      
      Log.debug("Aspace OIDC: Received callback for user #{username}.")
      if username && email
        aspace_groups = ASOidcUtil.get_aspace_groups(auth_hash, oidc_config)
        Log.debug("Aspace OIDC: Assigned groups are #{aspace_groups}.")
        auth_hash[:info][:username] = username # set username, checked in backend
        auth_hash[:info][:email] = email # ensure email is set in info
        auth_hash[:info][:groups] = aspace_groups
        File.open(pw_path, 'w') { |f| f.write(JSON.generate(auth_hash)) }
        deny_without_group = true
        if oidc_config.key?(:role_mapping) && oidc_config[:role_mapping].key?(:deny_without_group)
          deny_without_group = oidc_config[:role_mapping][:deny_without_group]
        end
        Log.debug("Aspace OIDC: deny without group setting is #{deny_without_group}.")
        if deny_without_group == false || aspace_groups.length() > 0
          backend_session = User.login(username, pw)

          if backend_session
            User.establish_session(self, backend_session, username)
            load_repository_list
          else
            Log.error("Aspace OIDC: Did not receive backend session. Login problem in backend.")
            flash[:error] = I18n.t("plugins.aspace-oidc.login_error")
          end
    
          File.delete pw_path if File.exist? pw_path
        else
          Log.debug("Aspace OIDC: No groups were assigned to user #{username} and login without group assignment is prohibited.")
          flash[:error] = I18n.t("plugins.aspace-oidc.permission_error")
        end
      else
        Log.error("Aspace OIDC: Either username or e-mail are not set. Cannot continue.")
      end
    else
      Log.error("Aspace OIDC: Could not retrieve configuration for this provider.")
      flash[:error] = I18n.t("plugins.aspace-oidc.config_error")
    end

    Log.debug("Aspace OIDC: Login for user #{username} was successful. Redirecting.")
    redirect_to controller: :welcome, action: :index
  end

  def failure
    flash[:error] = params[:message]
    redirect_to controller: :welcome, action: :index
  end

  protected

  def auth_hash
    request.env['omniauth.auth']
  end
end
