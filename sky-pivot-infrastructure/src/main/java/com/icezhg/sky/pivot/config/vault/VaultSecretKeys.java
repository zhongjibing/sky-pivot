package com.icezhg.sky.pivot.config.vault;

public final class VaultSecretKeys {

    public static final String MOUNT = "secret";
    public static final String BASE_PATH = "sky-pivot";

    public static final String HOFMANN_SERVER_KEY_SEED = "hofmann/server-key-seed-hex";
    public static final String HOFMANN_OPRF_SEED = "hofmann/oprf-seed-hex";
    public static final String HOFMANN_OPRF_MASTER_KEY = "hofmann/oprf-master-key-hex";

    public static final String JWT_ST_SECRET = "jwt/st-secret-hex";

    public static final String DATABASE_PASSWORD = "database/password";

    public static final String TLS_CERTIFICATE = "tls/certificate";
    public static final String TLS_PRIVATE_KEY = "tls/private-key";

    public static final String[] REQUIRED_SECRETS = {
        HOFMANN_SERVER_KEY_SEED,
        HOFMANN_OPRF_SEED,
        HOFMANN_OPRF_MASTER_KEY,
        JWT_ST_SECRET,
        DATABASE_PASSWORD
    };

    private VaultSecretKeys() {
    }
}
