package openfoodfacts.github.keycloak.events;

import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.models.UserModel;

import java.util.HashMap;

public class RedisEventListenerProvider implements EventListenerProvider {
    private static final Logger log = Logger.getLogger(RedisEventListenerProvider.class);

    private final KeycloakSession session;
    private final RealmProvider model;
    private final Client client;

    public RedisEventListenerProvider(final KeycloakSession session, final String redisUrl) {
        if (session == null) {
            throw new IllegalArgumentException("session");
        }

        this.session = session;
        this.model = session.realms();
        this.client = new Client(redisUrl);
    }

    @Override
    public void onEvent(Event event) {
        log.debugf("New %s Event", event.getType());

        if (EventType.DELETE_ACCOUNT.equals(event.getType())) {
            event.getDetails().forEach((key, value) -> log.debugf("%s : %s", key, value));

            RealmModel realm = this.model.getRealm(event.getRealmId());
            UserModel user = this.session.users().getUserById(realm, event.getUserId());
            sendUserData(user, realm);
        }
    }

    @Override
    public void onEvent(AdminEvent adminEvent, boolean b) {
        log.debug("onEvent(AdminEvent)");
        log.debugf("Resource path: %s", adminEvent.getResourcePath());
        log.debugf("Resource type: %s", adminEvent.getResourceType());
        log.debugf("Operation type: %s", adminEvent.getOperationType());
        if (ResourceType.USER.equals(adminEvent.getResourceType())
                && OperationType.DELETE.equals(adminEvent.getOperationType())) {
            RealmModel realm = this.model.getRealm(adminEvent.getRealmId());
            UserModel user = this.session.users().getUserById(realm, adminEvent.getResourcePath().substring(6));
            sendUserData(user, realm);
        }
    }

    private void sendUserData(final UserModel user, final RealmModel realm) {
        HashMap<String, String> data = new HashMap<>();
        data.put("id", user.getId());
        data.put("email", user.getEmail());
        data.put("userName", user.getUsername());
        data.put("realm", realm.getName());

        try {
            this.client.postUserDeleted(data);
            log.debug("A new user has been created and post API");
        } catch (Exception e) {
            log.errorf("Failed to call API: %s", e);
        }
    }

    @Override
    public void close() {
        try {
            this.client.close();
        } catch (Exception e) {
            log.errorf("Failed to close client: %s", e);
        }
    }
}
