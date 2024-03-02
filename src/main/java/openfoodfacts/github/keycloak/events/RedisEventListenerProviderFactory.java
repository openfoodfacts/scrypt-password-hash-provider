package openfoodfacts.github.keycloak.events;

import org.keycloak.Config;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class RedisEventListenerProviderFactory implements EventListenerProviderFactory {
    private String redisUrl;

    @Override
    public EventListenerProvider create(KeycloakSession keycloakSession) {
        return new RedisEventListenerProvider(keycloakSession, this.redisUrl);
    }

    @Override
    public void init(Config.Scope scope) {
        this.redisUrl = scope.get("redisUrl");
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return "redis-event-listener";
    }
}
