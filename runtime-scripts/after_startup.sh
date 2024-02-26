function wait_for_keycloak() {
  local -r MAX_WAIT=60
  local config_command
  local wait_time

  config_command="/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 --user $KEYCLOAK_ADMIN --password $KEYCLOAK_ADMIN_PASSWORD --realm master"
  wait_time=0

  # Waiting for the application to return a 200 status code.
  until ${config_command}; do
    if [[ ${wait_time} -ge ${MAX_WAIT} ]]; then
      echo "The application service did not start within ${MAX_WAIT} seconds. Aborting."
      exit 1
    else
      echo "Waiting (${wait_time}/${MAX_WAIT}) ..."
      sleep 1
      ((++wait_time))
    fi
  done

  echo "Keycloak is now up and running."
}

# Waiting for Keycloak to start before proceeding with the configurations.
wait_for_keycloak

# Keycloak is running.

echo "Calling configure_keycloak"
# shellcheck disable=SC2154 # CUSTOM_SCRIPTS_DIR is defined in Dockerfile.
# Run migrations and things here
echo "End of configure_keycloak"
