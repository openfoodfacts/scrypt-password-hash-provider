package be.cronos.keycloak.utils;

import java.util.Base64;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.credential.PasswordCredentialModel;

import be.cronos.keycloak.credential.hash.Argon2PasswordHashProviderFactory;
import be.cronos.keycloak.policy.Argon2HashLengthPasswordPolicyProviderFactory;

/**
 * @author <a href="mailto:dries.eestermans@is4u.be">Dries Eestermans</a>
 */
public class Argon2HelperTest {

    private static final String ALGORITHM = Argon2PasswordHashProviderFactory.ID;
    private static final int DEFAULT_COST = 16384;

    private static final int DEFAULT_BLOCK_SIZE = 8;

    private static final int DEFAULT_PARALLELISM = 1;

    private static byte[] salt;

    @BeforeEach
    public void generateSalt() {
        salt = Argon2Helper.getSalt(16);
    }

    // region: argon2d
    @Test
    public void testArgon2dHashAndVerifySamePassword() {
        int cost = DEFAULT_COST;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            cost,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, cost, hash);
        passwordCredentialModel.setSecretData(hash);
        setAdditionalParameters(
            passwordCredentialModel,
            cost,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM
        );
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    private static void setAdditionalParameters(PasswordCredentialModel passwordCredentialModel, int N, int r, int p) {
        MultivaluedHashMap<String, String> additionalParameters = passwordCredentialModel.getPasswordCredentialData().getAdditionalParameters();
        additionalParameters.putSingle("N", Integer.toString(N));
        additionalParameters.putSingle("r", Integer.toString(r));
        additionalParameters.putSingle("p", Integer.toString(p));
    }

    @Test
    public void testArgon2dHashAndVerifyDifferentPassword() {
        int cost = DEFAULT_COST;
        String rawPassword = "testargon2d";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            cost,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, cost, hash);
        passwordCredentialModel.setSecretData(hash);
        setAdditionalParameters(
            passwordCredentialModel,
            cost,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM
        );
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedHash() {
        String rawPassword = "testargon2d";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("v3evK1HhIHKHRnRNWqEfZA"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        setAdditionalParameters(
            passwordCredentialModel,
            DEFAULT_COST
        );
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testMangaDexArgon2idPassword() {
        var rawPassword = "testing123";
        var hashPassword = "$argon2id$v=19$m=65536,t=4,p=1$ETNLJIojWhiW6jnhz0GitA$dReu5sV+s9VPGBqCe5nts02aXVOpNN4oFZSmubzi5Lg";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("ETNLJIojWhiW6jnhz0GitA"),
            DEFAULT_COST,
            hashPassword
        );
        passwordCredentialModel.setSecretData(hashPassword);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2dVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2d";
        String hash = "$argon2d$v=19$m=65536,t=1,p=1$v3evK1HhIHKHRnRNWqEfZA$T7G+ujnDpZN+kYuMngOb/2+/mIDpOn0VyLIh7B6LJiY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    // endregion: argon2d

    // region: argon2i
    @Test
    public void testArgon2iHashAndVerifySamePassword() {
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2iHashAndVerifyDifferentPassword() {
        String rawPassword = "testargon2i";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedHash() {
        String rawPassword = "testargon2i";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2iVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2i";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }
    // endregion: argon2i

    // region: argon2id
    @Test
    public void testArgon2idHashAndVerifySamePassword() {
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2idHashAndVerifyDifferentPassword() {
        String rawPassword = "testargon2id";
        String hash = Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword("different", passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedHash() {
        String rawPassword = "testargon2id";
        String hash = "$argon2id$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("zGFM95kyhWZyZv1Hhvjuog"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertTrue(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedWrongHash() {
        String rawPassword = "wrongpassword";
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$81E/xOo/2OUX15UAJgI3Eg$0Z83Ag5oE9MCEEVGL9NJNg6oFIVbU/FhpQkyyX+RNz0";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("81E/xOo/2OUX15UAJgI3Eg"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    @Test
    public void testArgon2idVerifyPredefinedWrongSalt() {
        String rawPassword = "testargon2id";
        String hash = "$argon2id$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }
    // endregion: argon2id

    // region: runtime exceptions
    @Test
    public void testHashPasswordHashEmptyPassword() {
        Assertions.assertThrows(
            RuntimeException.class,
            () -> Argon2Helper.hashPassword(
                null,
                salt,
                DEFAULT_COST,
                DEFAULT_BLOCK_SIZE,
                DEFAULT_PARALLELISM,
                Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
            )
        );
    }

    @Test
    public void testHashPasswordNoAlgorithm() {
        String rawPassword = "novariantdefined";
        String tamperedHash = "$$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, salt, DEFAULT_COST, tamperedHash);
        passwordCredentialModel.setSecretData(tamperedHash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }

    @Test
    public void testHashPasswordNegativeIterations() {
        int iterations = -1;
        String rawPassword = "novariantdefined";
        Executable exec = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            iterations,
            DEFAULT_BLOCK_SIZE,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, exec);
    }

    @Test
    public void testHashPasswordNoParallelism() {
        int parallelism = 0;
        String rawPassword = "novariantdefined";
        Executable call = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            DEFAULT_BLOCK_SIZE,
            parallelism,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, call);
    }

    @Test
    public void testHashPasswordNoMemory() {
        int memory = 0;
        String rawPassword = "novariantdefined";
        Executable call = () -> Argon2Helper.hashPassword(
            rawPassword,
            salt,
            DEFAULT_COST,
            memory,
            DEFAULT_PARALLELISM,
            Argon2HashLengthPasswordPolicyProviderFactory.DEFAULT_HASH_LENGTH
        );
        Assertions.assertThrows(RuntimeException.class, call);
    }

    @Test
    public void testVerifyPasswordInvalidAlgorithm() {
        String rawPassword = "testargon2id";
        String hash = "$argon2idd$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }

    @Test
    public void testVerifyPasswordNonsenseData() {
        String rawPassword = "testargon2id";
        String hash = "nonsense";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(ALGORITHM, "".getBytes(), DEFAULT_COST, hash);
        passwordCredentialModel.setSecretData(hash);
        Assertions.assertThrows(RuntimeException.class, () -> Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel));
    }
    // endregion: runtime exceptions

    // region: wrong algorithm in hash

    @Test
    public void testVerifyPasswordIncorrectAlgorithm() {
        String rawPassword = "testargon2id";
        // it should argon2id
        String hash = "$argon2i$v=19$m=65536,t=1,p=1$zGFM95kyhWZyZv1Hhvjuog$G78Vd4nXEqN0DKbF+qGj1pUNyEpEZmOWqEqlHFDllJY";
        PasswordCredentialModel passwordCredentialModel = PasswordCredentialModel.createFromValues(
            ALGORITHM,
            Base64.getDecoder().decode("zGFM95kyhWZyZv1Hhvjuog"),
            DEFAULT_COST,
            hash
        );
        passwordCredentialModel.setSecretData(hash);
        boolean verified = Argon2Helper.verifyPassword(rawPassword, passwordCredentialModel);
        Assertions.assertFalse(verified);
    }

    // endregion: wrong algorithm in hash

}
