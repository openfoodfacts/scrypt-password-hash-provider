package de.hangy.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
@Deprecated
public class ScryptMaxTimePasswordPolicyProviderFactory extends ScryptGenericPolicyProviderFactory {
    public static final String ID = "scryptMaxTime";

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "scrypt Maximum Time (in ms)";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(1000);
    }

}
