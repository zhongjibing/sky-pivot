package com.icezhg.sky.pivot.config.vault;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Vault Secrets Tests")
class VaultSecretsTest {

    @Test
    @DisplayName("Should store and retrieve secret")
    void shouldStoreAndRetrieveSecret() {
        VaultSecrets secrets = new VaultSecrets();
        secrets.put("test-key", "test-value");
        assertEquals("test-value", secrets.get("test-key"));
    }

    @Test
    @DisplayName("Should throw when getting unknown secret")
    void shouldThrowWhenGettingUnknownSecret() {
        VaultSecrets secrets = new VaultSecrets();
        assertThrows(IllegalStateException.class, () -> secrets.get("unknown-key"));
    }

    @Test
    @DisplayName("Should return false for allRequiredLoaded when secrets missing")
    void shouldReturnFalseWhenSecretsMissing() {
        VaultSecrets secrets = new VaultSecrets();
        assertFalse(secrets.allRequiredLoaded());
    }

    @Test
    @DisplayName("Should return true for allRequiredLoaded when all required secrets loaded")
    void shouldReturnTrueWhenAllRequiredLoaded() {
        VaultSecrets secrets = new VaultSecrets();
        for (String key : VaultSecretKeys.REQUIRED_SECRETS) {
            secrets.put(key, "value-for-" + key);
        }
        assertTrue(secrets.allRequiredLoaded());
        assertEquals(VaultSecretKeys.REQUIRED_SECRETS.length, secrets.loadedCount());
    }

    @Test
    @DisplayName("Should check if individual secret is loaded")
    void shouldCheckIfIndividualSecretLoaded() {
        VaultSecrets secrets = new VaultSecrets();
        assertFalse(secrets.isLoaded("test-key"));
        secrets.put("test-key", "val");
        assertTrue(secrets.isLoaded("test-key"));
    }

    @Test
    @DisplayName("Should return typed accessors correctly")
    void shouldReturnTypedAccessors() {
        VaultSecrets secrets = new VaultSecrets();
        secrets.put(VaultSecretKeys.HOFMANN_SERVER_KEY_SEED, "server-seed-hex");
        secrets.put(VaultSecretKeys.HOFMANN_OPRF_SEED, "oprf-seed-hex");
        secrets.put(VaultSecretKeys.HOFMANN_OPRF_MASTER_KEY, "oprf-master-hex");
        secrets.put(VaultSecretKeys.JWT_ST_SECRET, "st-secret-hex");
        secrets.put(VaultSecretKeys.DATABASE_PASSWORD, "db-password");

        assertEquals("server-seed-hex", secrets.getHofmannServerKeySeedHex());
        assertEquals("oprf-seed-hex", secrets.getHofmannOprfSeedHex());
        assertEquals("oprf-master-hex", secrets.getHofmannOprfMasterKeyHex());
        assertEquals("st-secret-hex", secrets.getJwtStSecretHex());
        assertEquals("db-password", secrets.getDatabasePassword());
    }

    @Test
    @DisplayName("Should return 0 loaded count for empty store")
    void shouldReturnZeroForEmptyStore() {
        VaultSecrets secrets = new VaultSecrets();
        assertEquals(0, secrets.loadedCount());
    }
}
