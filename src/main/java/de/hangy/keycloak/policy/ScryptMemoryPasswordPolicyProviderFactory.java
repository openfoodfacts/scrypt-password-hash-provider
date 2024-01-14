package de.hangy.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class ScryptMemoryPasswordPolicyProviderFactory extends ScryptGenericPolicyProviderFactory {
    public static final String ID = "scryptMemory";
    public static final int DEFAULT_MEMORY = 65536;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "scrypt Memory Usage (KB)";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_MEMORY);
    }

}
