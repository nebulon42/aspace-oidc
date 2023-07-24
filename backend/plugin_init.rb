ArchivesSpaceService.loaded_hook do
  class AuthenticationManager

    def self.authenticate(username, password)
      authentication_sources.each do |source|
        begin
          Log.debug("Processing source #{source.inspect}")
          user = User.find(:username => username)
  
          # System users are only authenticated locally.
          next if (user && user.is_system_user == 1 && source != DBAuth)
  
          #ANW-97: check if user is inactive
          next if (user && user.is_active_user != 1)

          # If configured prevent authentication attempts for existing users via a
          # different source. Use case: don't allow an LDAP user to authenticate via
          # the database because they had a password set at some point
          if AppConfig[:authentication_restricted_by_source] && user && user.source != 'local'
            if user.source != source.name
              Log.warn("Restricted source for #{user.username} [#{user.source}]: #{source.name}")
              next
            end
          end
  
          data = source.authenticate(username, password)

          user_groups = nil
          if data.respond_to?('length') && data.length() > 1
            jsonmodel_user = data.first
            user_groups = data[1]
          else
            jsonmodel_user = data
          end

          if !jsonmodel_user
            next
          end
  
          if user
            begin
              RequestContext.put(:apply_admin_access, jsonmodel_user[:is_admin])
              user.update_from_json(jsonmodel_user,
                                    :source => source.name,
                                    :lock_version => user.lock_version)
            rescue Sequel::NoExistingObject => e
              # We'll swallow these because they only really mean that the user
              # logged in twice simultaneously.  As long as one of the updates
              # succeeded it doesn't really matter.
              user = User.find(:username => username)
            end

            if user_groups
              existing_groups = Hash.new
              user.group_dataset.each do |group|
                existing_groups[group[:repo_id].to_s + '/' + group[:id].to_s] = Hash['repository' => group[:repo_id], 'group' => group[:id]]
              end

              change_groups = Hash.new
              idp_groups = Hash.new
              user_groups.each do |item|
                key = item['repository'].to_s + '/' + item['group'].to_s
                idp_groups[key] = item
                change_groups[key] = Hash['action' => 'add', 'repository' => item['repository'], 'group' => item['group']] unless existing_groups.include?(key)
              end

              existing_groups.each do |key,item|
                change_groups[key] = Hash['action' => 'remove', 'repository' => item['repository'], 'group' => item['group']] unless idp_groups.include?(key)
              end

              change_groups.each do |key,item|
                Log.debug("#{item['action']} to/from #{item['repository']}/#{item['group']}")
                RequestContext.open(:repo_id => item['repository']) do
                  group = Group.get_or_die(item['group'])
                  if group
                    if item['action'] == 'add'
                      group.add_user(user)
                    elsif item['action'] == 'remove'
                      group.remove_user(user)
                    end
                    group.class.broadcast_changes
                  end
                end
              end
            end
          else
            DB.attempt {
              user = User.create_from_json(jsonmodel_user, :source => source.name)
            }.and_if_constraint_fails {
              return authenticate(username, password)
            }

            if user_groups
              user_groups.each do |item|
                Log.debug("add to #{item['repository']}/#{item['group']}")
                RequestContext.open(:repo_id => item['repository']) do
                  group = Group.get_or_die(item['group'])
                  if group
                    group.add_user(user)
                  end
                  group.class.broadcast_changes
                end
              end
            end
          end
  
          return user
        rescue
          Log.error("Error communicating with authentication source #{source.inspect}: #{$!}")
          Log.exception($!)
          next
        end
      end
  
      nil
    end
  end
end