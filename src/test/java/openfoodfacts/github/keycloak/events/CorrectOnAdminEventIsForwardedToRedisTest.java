package openfoodfacts.github.keycloak.events;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.models.KeycloakSession;
import redis.clients.jedis.params.XReadParams;
import redis.clients.jedis.resps.StreamEntry;

import com.redis.testcontainers.*;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.events.admin.OperationType;
import org.keycloak.events.admin.ResourceType;
import redis.clients.jedis.*;

@Testcontainers
public class CorrectOnAdminEventIsForwardedToRedisTest {

    @Container
    private static RedisContainer container = new RedisContainer(
            RedisContainer.DEFAULT_IMAGE_NAME.withTag(RedisContainer.DEFAULT_TAG));

    @Test
    void testCorrectOnAdminEventIsForwarded() {
        // Arrange
        String redisURI = container.getRedisURI();
        openfoodfacts.github.keycloak.events.RedisEventListenerProviderFactory factory = new openfoodfacts.github.keycloak.events.RedisEventListenerProviderFactory();
        factory.init(Utils.createScope(redisURI));

        KeycloakSession session = Utils.createKeycloakSession();
        EventListenerProvider eventListenerProvider = factory.create(session);
        try (JedisPooled jedis = new JedisPooled(redisURI)) {
            // Act
            AdminEvent adminEvent = new AdminEvent();
            adminEvent.setOperationType(OperationType.DELETE);
            adminEvent.setResourceType(ResourceType.USER);
            adminEvent.setRealmId("open-products-facts");
            adminEvent.setResourcePath("users/theUserId");
            eventListenerProvider.onEvent(adminEvent, false);

            // Assert
            Map<String, StreamEntryID> streamQuery = new HashMap<>();
            streamQuery.put("user-deleted", new StreamEntryID());
            List<Map.Entry<String, List<StreamEntry>>> result = jedis.xread(XReadParams.xReadParams(), streamQuery);
            Assertions.assertEquals(1, result.size());
            final Map.Entry<String, List<StreamEntry>> entry = result.get(0);
            Assertions.assertEquals("user-deleted", entry.getKey());
            final List<StreamEntry> streamEntries = entry.getValue();
            Assertions.assertEquals(1, streamEntries.size());
            final StreamEntry streamEntry = streamEntries.get(0);
            final Map<String, String> fields = streamEntry.getFields();
            Assertions.assertEquals("theUserId", fields.get("id"));
            Assertions.assertEquals("someUser@example.org", fields.get("email"));
            Assertions.assertEquals("theUserName", fields.get("userName"));
            Assertions.assertEquals("open-products-facts", fields.get("realm"));
        }
    }
}
