package com.icezhg.sky.pivot.opaque;

public final class OpaqueConstants {

    public static final String CONTEXT = "sky-pivot-v1";

    public static final String OPRF_SUITE = "P256_SHA256";

    public static final int ARGON2_MEMORY_KIB = 65536;
    public static final int ARGON2_ITERATIONS = 3;
    public static final int ARGON2_PARALLELISM = 1;

    public static final long ST_TTL_SECONDS = 15 * 60;
    public static final long AT_TTL_SECONDS = 2 * 60 * 60;

    public static final int MAX_LOGIN_START_PER_MINUTE = 10;

    public static final String TOKEN_TYPE_ST = "ST";
    public static final String TOKEN_TYPE_AT = "AT";
    public static final String TOKEN_TYPE_REFRESH = "REFRESH";

    public static final int SEED_LENGTH_BYTES = 32;

    public static final String ALG_EDDSA = "EdDSA";

    private OpaqueConstants() {
    }
}
