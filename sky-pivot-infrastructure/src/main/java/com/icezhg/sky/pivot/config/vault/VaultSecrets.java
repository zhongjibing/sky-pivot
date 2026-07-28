package com.icezhg.sky.pivot.config.vault;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class VaultSecrets {

    private final Map<String, String> secrets = new ConcurrentHashMap<>();

    public void put(String key, String value) {
        secrets.put(key, value);
    }

    public String get(String key) {
        String value = secrets.get(key);
        if (value == null) {
            throw new IllegalStateException("Vault secret not loaded: " + key);
        }
        return value;
    }

    public String getHofmannServerKeySeedHex() {
        return get(VaultSecretKeys.HOFMANN_SERVER_KEY_SEED);
    }

    public String getHofmannOprfSeedHex() {
        return get(VaultSecretKeys.HOFMANN_OPRF_SEED);
    }

    public String getHofmannOprfMasterKeyHex() {
        return get(VaultSecretKeys.HOFMANN_OPRF_MASTER_KEY);
    }

    public String getJwtStSecretHex() {
        return get(VaultSecretKeys.JWT_ST_SECRET);
    }

    public String getDatabasePassword() {
        return get(VaultSecretKeys.DATABASE_PASSWORD);
    }

    public String getTlsCertificate() {
        return get(VaultSecretKeys.TLS_CERTIFICATE);
    }

    public boolean isLoaded(String key) {
        return secrets.containsKey(key);
    }

    public boolean allRequiredLoaded() {
        for (String key : VaultSecretKeys.REQUIRED_SECRETS) {
            if (!secrets.containsKey(key)) {
                return false;
            }
        }
        return true;
    }

    public int loadedCount() {
        return secrets.size();
    }
}
