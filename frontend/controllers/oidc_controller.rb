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
    if AppConfig[:oidc_definitions]
      AppConfig[:oidc_definitions].each do |oidc_definition|
        if oidc_definition[:config][:name] == auth_hash[:provider]
          oidc_config = oidc_definition
          break
        end
      end
    end

    if oidc_config
      email = ASOidcUtil.get_email(auth_hash)
      if oidc_config.key?(:username_field)
        username = ASOidcUtil.get_field(auth_hash, oidc_config[:username_field])
      else
        username = email
        # usernames cannot be email addresses (legacy) and will be downcased:
        # https://github.com/archivesspace/archivesspace/blob/master/backend/app/model/user.rb#L117-L121
        username = username.split('@').first.downcase
      end
      
      puts "#{auth_hash}"
      Log.debug("Aspace OIDC: Received callback for user #{username}.")
      if username && email
        aspace_groups = ASOidcUtil.get_aspace_groups(auth_hash, oidc_config)
        auth_hash[:info][:username] = username # set username, checked in backend
        auth_hash[:info][:email] = email # ensure email is set in info
        auth_hash[:info][:groups] = aspace_groups
        File.open(pw_path, 'w') { |f| f.write(JSON.generate(auth_hash)) }
        deny_without_group = true
        if oidc_config.key?(:group_mapping) && oidc_config[:group_mapping].key?(:deny_without_group)
          deny_without_group = oidc_config[:group_mapping][:deny_without_group]
        end
        if deny_without_group == false || aspace_groups.length() > 0
          puts 'calling login'
          backend_session = User.login(username, pw)

          if backend_session
            User.establish_session(self, backend_session, username)
            load_repository_list
          else
            flash[:error] = 'Authentication error, unable to login.'
          end
    
          File.delete pw_path if File.exist? pw_path
        else
          flash[:error] = 'You do not have permissions to login.'
        end
      end
    else
      flash[:error] = 'Could not retrieve OIDC configuration.'
    end

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
