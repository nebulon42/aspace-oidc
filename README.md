# ArchivesSpace OIDC

Configure ArchivesSpace as a service provider (SP) for OIDC authentication.
*The plugin delegates authentication to the configured identity provider (IDP).*

Strategies tested:

- [OIDC](https://github.com/netsphere-labs/omniauth-openid-connect/)

## Overview

Enabling this plugin will:

- Provide Identity Provider (IDP) Sign In link/s
- The link will redirect the user to the IDP login portal
- If successful the user will have a user record created in ArchivesSpace
- User group membership is handled by mapping IDP groups to ArchivesSpace groups. IDP is the master

## Configuration

```ruby
AppConfig[:authentication_sources] = [
  {
    model: 'ASOidc',
    label: 'My IDP',
    show_login_form: false,
    username_field: 'extra.raw_info.preferred_username',
    groups_field: 'extra.raw_info.groups',
    group_mapping: {
      deny_without_group: true,
      admin: '/my/admin/group',
      repositories: [
        {
          mapping: '/my/archivesspace/my_repo/repository-managers',
          group: 5,
          repository: 2
        }
      ]
    },
    config: {
      name: 'keycloak',
      issuer: 'https://my.idp.com/auth/realms/Realm',
      discovery: true,
      send_nonce: false,
      scope: [:openid, :profile, :email, :groups],
      client_options: {
        redirect_uri: 'http://localhost:3000/auth/keycloak/callback',
        identifier: 'archivesspace',
        secret: 'SECRET'
      }
    }
  }
]

# add the plugin to the list
AppConfig[:plugins] << "aspace-oidc"
```

Add / change providers as needed and refer to the project documentation
for configuration details. There are many more configuration options than shown
above.

## Credits and License

This project is based on [aspace-oauth](https://github.com/lyrasis/aspace-oauth) by Lyrasis.
This project is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
