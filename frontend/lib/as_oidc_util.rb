# frozen_string_literal: true

module ASOidcUtil
  def self.get_email(auth)
    email = nil
    if auth[:info].key?(:email) && !auth[:info][:email].nil?
      email = auth[:info][:email]
    elsif auth[:extra].key?(:email) && !auth[:extra][:email].nil?
      email = auth[:extra][:email]
    elsif auth[:extra].key?(:response_object)
      if auth[:extra][:response_object].name_id
        email = auth[:extra][:response_object].name_id
      end
    end
    email
  end

  def self.get_field(auth, search)
    field = nil
    parts = search.split('.')
    if parts.length() > 1
      if auth.key?(parts[0])
        field = self.get_field(auth[parts[0]], parts.drop(1).join('.'))
      end
    else
      if auth.key?(search)
        field = auth[search]
      end
    end
    field
  end

  def self.get_aspace_groups(auth, config)
    aspace_groups = Hash.new
    if config.key?(:groups_field)
      groups = self.get_field(auth, config[:groups_field])
      if groups.length() > 0
        if config.key?(:group_mapping)
          if config[:group_mapping].key?(:admin) && groups.include?(config[:group_mapping][:admin][:mapping])
            aspace_groups['admin'] = Hash['repository' => config[:group_mapping][:admin][:repository], 'group' => config[:group_mapping][:admin][:group]]
          end
          if config[:group_mapping].key?(:repositories)
            config[:group_mapping][:repositories].each do |item|
              if groups.include?(item[:mapping])
                aspace_groups[item[:mapping]] = Hash['repository' => item[:repository], 'group' => item[:group]]
              end
            end
          end
        end
      end
    end
    aspace_groups
  end

  def self.show_login_form
    show_login_form = true
    if AppConfig[:oidc_definitions]
      oidc_config = nil
      AppConfig[:oidc_definitions].each do |oidc_definition|
        if oidc_definition[:model] == 'ASOidc'
          oidc_config = oidc_definition
          break
        end
      end

      if oidc_config && oidc_config.key?(:show_login_form)
        show_login_form = oidc_config[:show_login_form]
      end
    end
    show_login_form
  end
end
