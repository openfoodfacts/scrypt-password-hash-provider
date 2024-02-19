# Running Keycloak standalne

First, run `make build` to create the realm.json file with variables substituted. It seems that the standalone import for keycloak does not interpolate variables https://github.com/keycloak/keycloak/issues/12069

Then use `docker compose up -d --build` to build and run the container.

To see how a user logs in you can navigate to: http://localhost:5600/realms/open-products-facts/account/#/

# Major Workstreams

## First Release

### User Migration

This is mostly taken care of. The scrypt has provider ensures users will not need to change their passwords. [README.md](src/README.md)

### Secrity

[ ] Figure out how applications can register a client_id and get a client_secret

Steps to creating a client:

POST /admin/realms/open-products-facts/clients

```
{
    "clientId": "{new client}",
    "secret": "{new secret}",
    "directAccessGrantsEnabled": true,
    "serviceAccountsEnabled": true
}
```

Get the client id:

GET /admin/realms/open-products-facts/clients?clientId={new client}

Get the user for the client:

GET /admin/realms/{realm}/clients/{id}/service-account-user

Following should probably be done by linking the user to a group, but ad-hoc...

Get the realm-management client

GET /admin/realms/open-products-facts/clients?clientId=realm-management

Get the id of the manage-users role:

GET /admin/realms/open-products-facts/users/{service-account-user-id}/role-mappings/clients/{realm-management-id}/available

Assign the role

POST /admin/realms/{realm}/users/{service-account-user-id}/role-mappings/clients/{realm-management-id}

```
[{
    "id": "{Id from previous get}",
    "name": "manage-users"
}]
```


[ ] Work out how to limit access to the management console
[ ] Make sure any tools that can export users are disabled

### Database

Need to move storage to Postgres. Will also need a script to update the user attributes to a text column https://stackoverflow.com/questions/44851052/max-size-of-custom-user-attribute-in-keycloak

### Theming

Need to decide how similar we want to make the screens to the main pages. Some issues to consider:

 - How the locale is shown and passed through
 - Displaying current banners, e.g. donation prompts
 - General headers and footers

It looks like the CSS classes are very specific and so I suspect these could change with Keycloak releases. We therefore probably want a robust set of tests to ensure that themes are being applied correctly.

Currently the common.css file has to be copied between theme pages (account, login, etc.). Tried using a symlink but this didn't work.

### Localizaiton

We will need to ensure that all of the current OFF locales are covered with suitable translations.

Note that the default account theme, keycloak.v3, doesn't support localization properly. This is [fixed](https://github.com/keycloak/keycloak/issues/22507) but won't be available until verison 24.0.0. Still using keycloack.v3 for now though as it supports declarative user properties without having to build a custom UI.

[ ] Setup Crowdin yaml and GitHub actions
[ ] Ensure language parameter is passed to Keycloak and back to calling app

### Fields

All of the user editable fields need to be available on the account UI with any necessary validation.

Pick lists can be localized using this kind of structure:

```
    {
      "name": "country",
      "displayName": "${country}",
      "validations": {
        "options": {
          "options": [
            "uk",
            "es",
            "fr"
          ]
        }
      },
      "annotations": {
        "inputType": "select",
        "inputOptionLabels": {
          "uk": "${united-kingdom}",
          "es": "${spain}",
          "fr": "${france}"
        }
      },
      "permissions": {
        "view": [
          "admin",
          "user"
        ],
        "edit": [
          "admin",
          "user"
        ]
      }
    }
```

Fetch the current language and country taxonomies from OFF as part of the release process to populate this.

We will probably stil need to retain User.sto files for now containing data the user doesn't see for compatibility with OPF, OBF and OPFF.

### Backward compatibility

Username password authentication is still needed for now, which will use the password grant type (deprecated in OAuth 2.1).

We still also need to provide minimal user forms for the Smoothie mobile app to scrape.

We will need to update OPF, OBF and OPPF branches to use the password grant type for authentication and ensure that all other account activities are delegated to OFF.

### Delete User

We will need an event listener to pick up the user deleted event so that user names can be wiped from contributions. Maybe create a table in the Keycloak database so we can track for other applications too.

## Deprecate Non-keycloak Authentication

### Mobile

We will need to update the mobile applicaiton to launch the keycloak login and account pages before we can deprecate the password grant type option.

### Client Credentials for APIs

API consumers will need to be set up as Clients in Keycloak. Need to figure out how the sign-up process will work.

## Deprecate User .sto Files

This can run in parallel witht the above. Will need more extensive updates to OPF, OBF and OPPF.

## Support Alternative Login

Once all apps are going through Keycloak for authentication we can start to support things like Social Login and Passkeys.
