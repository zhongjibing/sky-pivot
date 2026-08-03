package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("AccessTokenService Tests")
class AccessTokenServiceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final String TEST_DEVICE_KEY_HEX =
            "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6";
    private static final String TEST_DEVICE_PUBKEY_B64;
    private static final String TEST_DEVICE_ID = "test-device-uuid-001";

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    private static final byte[] BC_X509_HEADER = {
        0x30, 0x2a, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
        try {
            byte[] seed = HEX.parseHex(TEST_DEVICE_KEY_HEX);
            Ed25519PrivateKeyParameters bcPrivateKey = new Ed25519PrivateKeyParameters(seed, 0);
            byte[] pubKeyBytes = bcPrivateKey.generatePublicKey().getEncoded();
            TEST_DEVICE_PUBKEY_B64 = B64E.encodeToString(pubKeyBytes);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private AccessTokenService accessTokenService;
    private DeviceRepository deviceRepository;
    private RedisService redisService;
    private PrivateKey deviceSigningKey;

    @BeforeEach
    void setUp() throws Exception {
        deviceRepository = mock(DeviceRepository.class);
        redisService = new FakeRedisService();

        byte[] seed = HEX.parseHex(TEST_DEVICE_KEY_HEX);
        byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
        System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
        System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        deviceSigningKey = keyFactory.generatePrivate(pkcs8Spec);

        accessTokenService = new AccessTokenService(deviceRepository, redisService);
    }

    private Device createAuthorizedDevice() {
        Device device = new Device();
        device.setUserId(1L);
        device.setDeviceId(TEST_DEVICE_ID);
        device.setDeviceName("Test Device");
        device.setDeviceType("PC");
        device.setEd25519PublicKey(TEST_DEVICE_PUBKEY_B64);
        device.setAuthorized(true);
        device.setRevoked(false);
        return device;
    }

    private String generateAt(Long userId, String deviceId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject(userId.toString())
                .claim("did", deviceId)
                .claim("type", "AT")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(2 * 60 * 60)))
                .id(UUID.randomUUID().toString())
                .signWith(deviceSigningKey, Jwts.SIG.EdDSA)
                .compact();
    }

    private String generateExpiredAt(Long userId, String deviceId) {
        Instant past = Instant.now().minusSeconds(3600);
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject(userId.toString())
                .claim("did", deviceId)
                .claim("type", "AT")
                .issuedAt(Date.from(past.minusSeconds(7200)))
                .expiration(Date.from(past))
                .id(UUID.randomUUID().toString())
                .signWith(deviceSigningKey, Jwts.SIG.EdDSA)
                .compact();
    }

    @Test
    @DisplayName("AC-1: Valid AT signed by device private key should verify successfully")
    void shouldVerifyValidAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(1L, TEST_DEVICE_ID);
        var claims = accessTokenService.verifyAccessToken(at);

        assertEquals("1", claims.getSubject());
        assertEquals("AT", claims.get("type"));
        assertEquals(TEST_DEVICE_ID, claims.get("did"));
        assertNotNull(claims.getId());
        assertNotNull(claims.getExpiration());
    }

    @Test
    @DisplayName("AC-1: AT signed by different key should fail verification")
    void shouldRejectAtSignedByDifferentKey() throws Exception {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String wrongKeyHex = "d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6";
        byte[] wrongSeed = HEX.parseHex(wrongKeyHex);
        byte[] wrongPkcs8 = new byte[BC_PKCS8_HEADER.length + wrongSeed.length];
        System.arraycopy(BC_PKCS8_HEADER, 0, wrongPkcs8, 0, BC_PKCS8_HEADER.length);
        System.arraycopy(wrongSeed, 0, wrongPkcs8, BC_PKCS8_HEADER.length, wrongSeed.length);
        PKCS8EncodedKeySpec wrongSpec = new PKCS8EncodedKeySpec(wrongPkcs8);
        KeyFactory kf = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        PrivateKey wrongKey = kf.generatePrivate(wrongSpec);

        Instant now = Instant.now();
        String atWithWrongSig = Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject("1")
                .claim("did", TEST_DEVICE_ID)
                .claim("type", "AT")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(7200)))
                .id(UUID.randomUUID().toString())
                .signWith(wrongKey, Jwts.SIG.EdDSA)
                .compact();

        assertThrows(Exception.class, () -> accessTokenService.verifyAccessToken(atWithWrongSig));
    }

    @Test
    @DisplayName("AC-3: AT from revoked device should fail")
    void shouldRejectAtFromRevokedDevice() {
        Device revokedDevice = createAuthorizedDevice();
        revokedDevice.setRevoked(true);

        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(revokedDevice));

        String at = generateAt(1L, TEST_DEVICE_ID);
        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(at));
    }

    @Test
    @DisplayName("AT from unauthorized device should fail")
    void shouldRejectAtFromUnauthorizedDevice() {
        Device unauthDevice = createAuthorizedDevice();
        unauthDevice.setAuthorized(false);

        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(unauthDevice));

        String at = generateAt(1L, TEST_DEVICE_ID);
        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(at));
    }

    @Test
    @DisplayName("AT for non-existent device should fail")
    void shouldRejectAtForNonExistentDevice() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        String at = generateAt(1L, TEST_DEVICE_ID);
        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(at));
    }

    @Test
    @DisplayName("Expired AT should fail verification")
    void shouldRejectExpiredAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String expiredAt = generateExpiredAt(1L, TEST_DEVICE_ID);
        assertThrows(Exception.class, () -> accessTokenService.verifyAccessToken(expiredAt));
    }

    @Test
    @DisplayName("Token with wrong type claim should be rejected")
    void shouldRejectTokenWithWrongType() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        Instant now = Instant.now();
        String nonAtToken = Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject("1")
                .claim("did", TEST_DEVICE_ID)
                .claim("type", "ST")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(900)))
                .id(UUID.randomUUID().toString())
                .signWith(deviceSigningKey, Jwts.SIG.EdDSA)
                .compact();

        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(nonAtToken));
    }

    @Test
    @DisplayName("AT missing did claim should be rejected")
    void shouldRejectAtWithoutDidClaim() {
        Instant now = Instant.now();
        String noDidAt = Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject("1")
                .claim("type", "AT")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(7200)))
                .id(UUID.randomUUID().toString())
                .signWith(deviceSigningKey, Jwts.SIG.EdDSA)
                .compact();

        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(noDidAt));
    }

    @Test
    @DisplayName("AC-3: Blacklisted AT jti should fail verification")
    void shouldRejectBlacklistedAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(1L, TEST_DEVICE_ID);
        var claims = accessTokenService.verifyAccessToken(at);
        String jti = claims.getId();

        accessTokenService.revokeAt(jti);

        assertThrows(SecurityException.class, () -> accessTokenService.verifyAccessToken(at));
    }

    @Test
    @DisplayName("isAccessToken should return true for valid AT")
    void shouldIdentifyValidAt() {
        String at = generateAt(1L, TEST_DEVICE_ID);
        assertTrue(accessTokenService.isAccessToken(at));
    }

    @Test
    @DisplayName("isAccessToken should return false for null, blank, or garbage")
    void shouldReturnFalseForInvalidTokens() {
        assertFalse(accessTokenService.isAccessToken(null));
        assertFalse(accessTokenService.isAccessToken(""));
        assertFalse(accessTokenService.isAccessToken("   "));
        assertFalse(accessTokenService.isAccessToken("not.a.valid.jwt"));
    }

    @Test
    @DisplayName("getUserIdFromAt should extract userId correctly")
    void shouldExtractUserIdFromAt() {
        when(deviceRepository.findByUserIdAndDeviceId(42L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(42L, TEST_DEVICE_ID);
        assertEquals(42L, accessTokenService.getUserIdFromAt(at));
    }

    @Test
    @DisplayName("getDeviceIdFromAt should extract deviceId correctly")
    void shouldExtractDeviceIdFromAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(1L, TEST_DEVICE_ID);
        assertEquals(TEST_DEVICE_ID, accessTokenService.getDeviceIdFromAt(at));
    }

    @Test
    @DisplayName("tryValidate should return Optional.of(userId) for valid AT")
    void shouldTryValidateValidAt() {
        when(deviceRepository.findByUserIdAndDeviceId(7L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(7L, TEST_DEVICE_ID);
        Optional<Long> result = accessTokenService.tryValidate(at);
        assertTrue(result.isPresent());
        assertEquals(7L, result.get());
    }

    @Test
    @DisplayName("tryValidate should return Optional.empty() for invalid AT")
    void shouldTryValidateInvalidAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        String at = generateAt(1L, TEST_DEVICE_ID);
        Optional<Long> result = accessTokenService.tryValidate(at);
        assertTrue(result.isEmpty());
    }

    @Test
    @DisplayName("AT with tampered signature should fail")
    void shouldRejectTamperedAt() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String at = generateAt(1L, TEST_DEVICE_ID);
        String[] parts = at.split("\\.");
        String tampered = parts[0] + "." + parts[1] + ".tamperedSig";

        assertThrows(Exception.class, () -> accessTokenService.verifyAccessToken(tampered));
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
    }
}
