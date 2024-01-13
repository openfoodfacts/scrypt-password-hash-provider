package be.cronos.keycloak.credential.hash;

import be.cronos.keycloak.policy.*;
import be.cronos.keycloak.utils.Argon2EncodingUtils;
import be.cronos.keycloak.utils.Argon2Helper;

import org.jboss.logging.Logger;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.PasswordPolicy;
import org.keycloak.models.credential.PasswordCredentialModel;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2PasswordHashProvider implements PasswordHashProvider {
    private static final Logger LOG = Logger.getLogger(Argon2PasswordHashProvider.class);

    private final String providerId;
    private final KeycloakSession session;

    public Argon2PasswordHashProvider(String providerId, KeycloakSession session) {
        this.providerId = providerId;
        this.session = session;
    }

    @Override
    public boolean policyCheck(PasswordPolicy policy, PasswordCredentialModel credential) {
        LOG.debugf("> policyCheck()");
        // Check it it is an argon2 encoded password.
        if (!providerId.equals(credential.getPasswordCredentialData().getAlgorithm())) {
            LOG.debugf("< policyCheck() -> Stored password uses a different algorithm and hence does not meet the Realm Password Policy.");
            return false;
        }
        // The stored password is a argon2 hash and hence checking the specific parameters of the policy is required.

        // Get the credential's Argon2 parameters
        Argon2EncodingUtils.Argon2Parameters storedArgon2Parameters = Argon2EncodingUtils
                .extractArgon2ParametersFromCredentials(credential.getPasswordSecretData().getValue(),
                        credential.getPasswordCredentialData().getAdditionalParameters());
        // Get the configured Argon2 parameters
        Argon2EncodingUtils.Argon2Parameters configuredArgon2Parameters = getConfiguredArgon2Parameters();

        // Perform a comparison on whether a re-hash is needed
        boolean meetsRealmPolicy = storedArgon2Parameters.getParallellism() == configuredArgon2Parameters.getParallellism()
                && storedArgon2Parameters.getCost() == configuredArgon2Parameters.getCost()
                && storedArgon2Parameters.getBlockSize() == configuredArgon2Parameters.getBlockSize();

        LOG.debugf("< policyCheck() -> Stored password meets Realm Password Policy = '%s'.", String.valueOf(meetsRealmPolicy));
        return meetsRealmPolicy;
    }

    @Override
    public PasswordCredentialModel encodedCredential(String rawPassword, int iterations) {
        LOG.debugf("> encodedCredential()");

        // Get the configured Argon2 parameters, or default values
        Argon2EncodingUtils.Argon2Parameters configuredArgon2Parameters = getConfiguredArgon2Parameters();

        // Generate a salt
        byte[] salt = Argon2Helper.getSalt(configuredArgon2Parameters.getSaltLength());

        // Retrieve an encoded Argon2 password hash
        String hash = Argon2Helper.hashPassword(
                rawPassword,
                salt,
                configuredArgon2Parameters.getCost(),
                configuredArgon2Parameters.getBlockSize(),
                configuredArgon2Parameters.getParallellism(),
                configuredArgon2Parameters.getHashLength()
        );

        LOG.debugf("< encodedCredential()");
        PasswordCredentialModel result = PasswordCredentialModel.createFromValues(providerId, salt, configuredArgon2Parameters.getCost(), hash);
        MultivaluedHashMap<String, String> additionalParameters = result.getPasswordCredentialData().getAdditionalParameters();
        Argon2EncodingUtils.setScryptParametersInAdditionalData(configuredArgon2Parameters, additionalParameters);
        return result;
    }

    @Override
    public boolean verify(String rawPassword, PasswordCredentialModel credential) {
        LOG.debugf("> verify()");

        // Verify whether the incoming password matches the stored password
        boolean passwordsMatch = Argon2Helper.verifyPassword(rawPassword, credential);

        LOG.debugf("< verify()");
        return passwordsMatch;
    }

    @Override
    public void close() {
        // noop
    }

    private <T> T getDefaultValue(String providerId, T defaultValue) {
        T ret;
        try {
            ret = this.session.getContext().getRealm().getPasswordPolicy().getPolicyConfig(providerId);
        } catch (Exception e) {
            ret = defaultValue;
        }
        if (ret == null) ret = defaultValue;
        return ret;
    }

    private Argon2EncodingUtils.Argon2Parameters getConfiguredArgon2Parameters() {
        return new Argon2EncodingUtils.Argon2Parameters(
                getDefaultValue(Argon2MemoryPasswordPolicyProviderFactory.ID, Argon2MemoryPasswordPolicyProviderFactory.DEFAULT_MEMORY),
                getDefaultValue(Argon2IterationsPasswordPolicyProviderFactory.ID, Argon2IterationsPasswordPolicyProviderFactory.DEFAULT_ITERATIONS),
                getDefaultValue(Argon2ParallelismPasswordPolicyProviderFactory.ID, Argon2ParallelismPasswordPolicyProviderFactory.DEFAULT_PARALLELISM),
                getDefaultValue(Argon2HashLengthPasswordPolicyProviderFactory.ID, Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH),
                getDefaultValue(Argon2SaltLengthPasswordPolicyProviderFactory.ID, Argon2SaltLengthPasswordPolicyProviderFactory.DEFAULT_SALT_LENGTH)
        );
    }
}
