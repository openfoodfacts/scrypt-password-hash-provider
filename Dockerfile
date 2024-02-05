# syntax = docker/dockerfile:1.2

ARG DEPENDENCY_KEYCLOAK_VERSION=23.0.6

# build a scrypt password provider for keycloak using maven
FROM maven:3-eclipse-temurin-17 AS builder

ARG DEPENDENCY_KEYCLOAK_VERSION
WORKDIR /build
COPY ./src /build/src
COPY ./pom.xml /build
RUN set -x && \
    mvn -B package -Drevision=${DEPENDENCY_KEYCLOAK_VERSION}

ARG DEPENDENCY_KEYCLOAK_VERSION
FROM quay.io/keycloak/keycloak:${DEPENDENCY_KEYCLOAK_VERSION}

USER root

# get the compiled scrypt password hash provider
COPY --from=builder --chown=keycloak:keycloak /build/target/keycloak-scrypt-*.jar /opt/keycloak/providers/

# Copy in the themes
COPY --chown=keycloak:keycloak themes/off /opt/keycloak/themes/off

# TODO: standalone import in Keycloak doesn't interpolate environment variables so have to build this outside
# Ideally ProductOwner would register itself as a client on first startup and store the secret in some kind of vault
# Should also be able to put this in a temporary directory and delete it afterwards
COPY --chown=keycloak:keycloak target/open-products-facts-realm.json /opt/keycloak/data/import/open-products-facts-realm.json
RUN set -x && \
    /opt/keycloak/bin/kc.sh import --file /opt/keycloak/data/import/open-products-facts-realm.json

RUN set -x && \
    /opt/keycloak/bin/kc.sh build && \
    chown -R keycloak:root /opt/keycloak

USER keycloak
