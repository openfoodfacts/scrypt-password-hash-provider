SHELL := /bin/bash

build:
	set -o allexport; source .env; set +o allexport; envsubst \$$PRODUCT_OPENER_OIDC_CLIENT_ID,\$$PRODUCT_OPENER_DOMAIN,\$$PRODUCT_OPENER_OIDC_CLIENT_SECRET < conf/open-products-facts-realm.json > target/open-products-facts-realm.json

up:
	docker compose up -d --build

dev: build up
