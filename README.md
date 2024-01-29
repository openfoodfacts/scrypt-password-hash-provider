# Keycloak scrypt

This is a password hash provider for Keycloak 20+ to support scrypt hashes.

This is a fork of [dreezey/argon2-password-hash-provider](https://github.com/dreezey/argon2-password-hash-provider) updated to work with mainline Keycloak and use scrypt instead.

The [original README is here](README.original.md). 

---

I has no long-term plan to support this fork; rather it's mainly a migration helper for a small subset of users in our systems using those systems.

However PRs etc are still welcome.

# Running Keycloak standalne

First, run `make build` to create the realm.json file with variables substituted. It seems that the standalone import for keycloak does not interpolate variables https://github.com/keycloak/keycloak/issues/12069

Then use `docker compose up -d --build` to build and run the container.

To see how a user logs in you can navigate to: http://localhost:5600/realms/open-products-facts/account/#/

