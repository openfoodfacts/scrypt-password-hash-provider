package openfoodfacts.github.keycloak.events;

import java.util.Map;

import com.fasterxml.jackson.databind.ObjectMapper;

import redis.clients.jedis.JedisPooled;

public class Client implements AutoCloseable {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final JedisPooled jedis;

    public Client(final String url) {
        this.jedis = new JedisPooled(url);
    }

    public void postUserDeleted(final Map<String, String> userDeletedEvents) {
        String json = MAPPER.convertValue(userDeletedEvents, String.class);
        jedis.publish("user-deleted", json);
    }

    @Override
    public void close() throws Exception {
        this.jedis.close();
    }

}
