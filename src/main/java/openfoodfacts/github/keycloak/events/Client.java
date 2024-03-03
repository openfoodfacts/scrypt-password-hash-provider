package openfoodfacts.github.keycloak.events;

import java.util.Map;

import redis.clients.jedis.JedisPooled;
import redis.clients.jedis.StreamEntryID;

public class Client implements AutoCloseable {

    private final JedisPooled jedis;

    public Client(final String url) {
        this.jedis = new JedisPooled(url);
    }

    public void postUserDeleted(final Map<String, String> userDeletedEvents) {
        jedis.xadd("user-deleted", StreamEntryID.NEW_ENTRY, userDeletedEvents);
    }

    @Override
    public void close() throws Exception {
        this.jedis.close();
    }

}
