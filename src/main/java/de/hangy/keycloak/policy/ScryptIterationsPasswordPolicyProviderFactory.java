package de.hangy.keycloak.policy;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class ScryptIterationsPasswordPolicyProviderFactory extends ScryptGenericPolicyProviderFactory {
    public static final String ID = "scryptIterations";
    public static final int DEFAULT_ITERATIONS = 1;

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayName() {
        return "scrypt Iterations";
    }

    @Override
    public String getDefaultConfigValue() {
        return String.valueOf(DEFAULT_ITERATIONS);
    }
}
