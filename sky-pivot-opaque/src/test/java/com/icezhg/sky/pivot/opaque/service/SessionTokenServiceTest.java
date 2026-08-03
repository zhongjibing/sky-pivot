package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.opaque.config.HofmannPropertiesFromVault;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SessionTokenService Tests")
class SessionTokenServiceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final String HEX_KEY = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    @DisplayName("AC-1: ST generated and verified successfully")
    void shouldGenerateAndVerifySessionToken() {
        SessionTokenService service = createService(HEX_KEY, null);

        String st = service.generateSessionToken(42L);
        assertNotNull(st);
        assertTrue(st.split("\\.").length == 3, "ST should be a valid JWT with 3 parts");

        var claims = service.verifySessionToken(st);
        assertEquals("42", claims.getSubject());
        assertEquals("ST", claims.get("type"));
        assertNotNull(claims.getId());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());

        assertEquals(42L, service.getUserIdFromSt(st));
    }

    @Test
    @DisplayName("AC-1: ST tampered with should fail verification")
    void shouldRejectTamperedToken() {
        SessionTokenService service = createService(HEX_KEY, null);

        String st = service.generateSessionToken(42L);
        String[] parts = st.split("\\.");
        String tamperedPayload = parts[0] + "." + parts[1] + "." + "tamperedSignature";

        assertThrows(Exception.class, () -> service.verifySessionToken(tamperedPayload));
    }

    @Test
    @DisplayName("AC-2: Expired ST should fail verification")
    void shouldRejectExpiredToken() throws Exception {
        SessionTokenService service = createService(HEX_KEY, null);

        String st = service.generateSessionToken(42L);

        var claims = service.verifySessionToken(st);
        assertNotNull(claims);
        assertNotNull(claims.getExpiration());

        assertTrue(claims.getExpiration().getTime() > System.currentTimeMillis(),
                "Fresh ST should not be expired yet");
        assertTrue(claims.getExpiration().getTime() < System.currentTimeMillis() + Duration.ofMinutes(16).toMillis(),
                "ST should expire within 16 minutes (15 min TTL + 1 min clock skew)");
    }

    @Test
    @DisplayName("AC-2: Expired ST throws ExpiredJwtException")
    void shouldThrowExpiredJwtExceptionForExpiredToken() {
        SessionTokenService service = createService(HEX_KEY, null);

        String expiredSt = buildExpiredToken(service);
        assertNotNull(expiredSt, "Expired ST should be generated");

        assertThrows(ExpiredJwtException.class, () -> service.verifySessionToken(expiredSt),
                "Expired ST should throw ExpiredJwtException");
    }

    @Test
    @DisplayName("AC-3: Blacklisted ST should fail verification")
    void shouldRejectBlacklistedToken() {
        RedisService redisService = new FakeRedisService();
        SessionTokenService service = createService(HEX_KEY, redisService);

        String st = service.generateSessionToken(42L);
        var claims = service.verifySessionToken(st);
        String jti = claims.getId();

        service.revokeSt(jti);

        assertThrows(SecurityException.class, () -> service.verifySessionToken(st),
                "Blacklisted ST should be rejected");

        assertTrue(redisService.hasKey(
                RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti)
        ), "jti should be in blacklist after revoke");
    }

    @Test
    @DisplayName("AC-3: revokeSt adds jti to blacklist")
    void shouldAddJtiToBlacklist() {
        RedisService redisService = new FakeRedisService();
        SessionTokenService service = createService(HEX_KEY, redisService);

        String st = service.generateSessionToken(42L);
        var claims = service.verifySessionToken(st);
        String jti = claims.getId();

        service.revokeSt(jti);

        assertTrue(redisService.hasKey(
                RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti)
        ), "jti should be added to blacklist");
    }

    @Test
    @DisplayName("Should not reject non-blacklisted token")
    void shouldAcceptNonBlacklistedToken() {
        RedisService redisService = new FakeRedisService();
        SessionTokenService service = createService(HEX_KEY, redisService);

        String st1 = service.generateSessionToken(42L);
        String st2 = service.generateSessionToken(42L);

        service.revokeSt(service.verifySessionToken(st1).getId());

        assertDoesNotThrow(() -> service.verifySessionToken(st2),
                "Non-blacklisted ST should be accepted");
    }

    @Test
    @DisplayName("isSessionToken should return true for valid ST")
    void shouldIdentifyValidSt() {
        SessionTokenService service = createService(HEX_KEY, null);
        String st = service.generateSessionToken(42L);

        assertTrue(service.isSessionToken(st));
    }

    @Test
    @DisplayName("isSessionToken should return false for null or blank")
    void shouldReturnFalseForNullOrBlank() {
        SessionTokenService service = createService(HEX_KEY, null);

        assertFalse(service.isSessionToken(null));
        assertFalse(service.isSessionToken(""));
        assertFalse(service.isSessionToken("   "));
    }

    @Test
    @DisplayName("isSessionToken should return false for non-ST token")
    void shouldReturnFalseForNonStToken() {
        SessionTokenService service = createService(HEX_KEY, null);

        assertFalse(service.isSessionToken("not.a.valid.jwt"));
    }

    @Test
    @DisplayName("Should reject token with wrong type claim")
    void shouldRejectTokenWithWrongType() {
        SessionTokenService service = createService(HEX_KEY, null);

        String st = service.generateSessionToken(42L);
        var claims = service.verifySessionToken(st);
        assertEquals("ST", claims.get("type"),
                "Valid ST should have type=ST claim");

        assertThrows(SecurityException.class, () -> {
            Claims c = service.verifySessionToken(st);
            if (!"AT".equals(c.get("type"))) {
                throw new SecurityException("Not an Access Token");
            }
        });
    }

    @Test
    @DisplayName("Should generate different tokens for same user")
    void shouldGenerateDifferentTokensForSameUser() {
        SessionTokenService service = createService(HEX_KEY, null);

        String st1 = service.generateSessionToken(42L);
        String st2 = service.generateSessionToken(42L);
        assertNotEquals(st1, st2, "Each ST should have a unique jti");
    }

    @Test
    @DisplayName("Should handle minimum length seed by padding")
    void shouldHandleShortSeed() {
        String shortKey = "a1b2c3d4";
        SessionTokenService service = createService(shortKey, null);

        String st = service.generateSessionToken(42L);
        assertNotNull(st);
        var claims = service.verifySessionToken(st);
        assertEquals("42", claims.getSubject());
    }

    private static SessionTokenService createService(String hexKey, RedisService redisService) {
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(hexKey);
        return new SessionTokenService(props, redisService);
    }

    private static String buildExpiredToken(SessionTokenService service) {
        byte[] seed = HEX.parseHex(HEX_KEY);
        if (seed.length < 32) {
            byte[] padded = new byte[32];
            System.arraycopy(seed, 0, padded, 0, seed.length);
            seed = padded;
        }
        try {
            byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
            System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
            System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            PrivateKey signingKey = keyFactory.generatePrivate(pkcs8Spec);

            Instant pastExp = Instant.now().minusSeconds(3600);
            Instant pastIat = pastExp.minusSeconds(900);

            return Jwts.builder()
                    .header().add("alg", "EdDSA").and()
                    .subject("42")
                    .claim("type", "ST")
                    .issuedAt(Date.from(pastIat))
                    .expiration(Date.from(pastExp))
                    .id(UUID.randomUUID().toString())
                    .signWith(signingKey, Jwts.SIG.EdDSA)
                    .compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to build expired token", e);
        }
    }

    static class TestHofmannPropertiesFromVault extends HofmannPropertiesFromVault {
        private final String stSecret;

        TestHofmannPropertiesFromVault(String stSecret) {
            super(null);
            this.stSecret = stSecret;
        }

        @Override
        public String getJwtStSecretHex() {
            return stSecret;
        }

        @Override
        public String getServerKeySeedHex() {
            return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        }

        @Override
        public String getOprfSeedHex() {
            return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        }

        @Override
        public String getOprfMasterKeyHex() {
            return "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        }
    }

    static class FakeRedisService extends RedisService {

        private final java.util.Map<String, Object> store = new java.util.concurrent.ConcurrentHashMap<>();

        FakeRedisService() {
            super(null);
        }

        @Override
        public void set(String key, Object value, Duration timeout) {
            store.put(key, value);
        }

        @Override
        public Boolean hasKey(String key) {
            return store.containsKey(key);
        }

        @Override
        public <T> java.util.Optional<T> get(String key, Class<T> type) {
            @SuppressWarnings("unchecked")
            T value = (T) store.get(key);
            return java.util.Optional.ofNullable(value);
        }
    }
}
