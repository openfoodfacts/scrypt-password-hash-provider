package openfoodfacts.github.keycloak.events;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import redis.clients.jedis.params.XReadParams;
import redis.clients.jedis.resps.StreamEntry;

import com.redis.testcontainers.*;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import redis.clients.jedis.*;

@Testcontainers
public class IncorrectOnEventIsNotForwardedToRedisTest {

    @Container
    private static RedisContainer container = new RedisContainer(
            RedisContainer.DEFAULT_IMAGE_NAME.withTag(RedisContainer.DEFAULT_TAG));

    @Test
    void testIncorrectOnEventIsNotForwarded() {
        // Arrange
        String redisURI = container.getRedisURI();
        openfoodfacts.github.keycloak.events.RedisEventListenerProviderFactory factory = new openfoodfacts.github.keycloak.events.RedisEventListenerProviderFactory();
        factory.init(Utils.createScope(redisURI));

        KeycloakSession session = Utils.createKeycloakSession();
        EventListenerProvider eventListenerProvider = factory.create(session);
        try (JedisPooled jedis = new JedisPooled(redisURI)) {
            // Act
            Event event = new Event();
            event.setType(EventType.CLIENT_DELETE);
            event.setRealmId("open-products-facts");
            event.setUserId("theUserId");
            eventListenerProvider.onEvent(event);

            // Assert
            Map<String, StreamEntryID> streamQuery = new HashMap<>();
            streamQuery.put("user-deleted", new StreamEntryID());
            List<Map.Entry<String, List<StreamEntry>>> result = jedis.xread(XReadParams.xReadParams(), streamQuery);
            Assertions.assertNull(result);
        }
    }
}
