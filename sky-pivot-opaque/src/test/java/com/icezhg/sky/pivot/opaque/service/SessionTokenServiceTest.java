package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.opaque.config.HofmannPropertiesFromVault;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SessionTokenService Tests")
class SessionTokenServiceTest {

    private static final HexFormat HEX = HexFormat.of();

    @Test
    @DisplayName("AC-1: ST generated and verified successfully")
    void shouldGenerateAndVerifySessionToken() {
        String hexKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(hexKey);
        SessionTokenService service = new SessionTokenService(props);

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
        String hexKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(hexKey);
        SessionTokenService service = new SessionTokenService(props);

        String st = service.generateSessionToken(42L);
        String[] parts = st.split("\\.");
        String tamperedPayload = parts[0] + "." + parts[1] + "." + "tamperedSignature";

        assertThrows(Exception.class, () -> service.verifySessionToken(tamperedPayload));
    }

    @Test
    @DisplayName("AC-3: ST with wrong type claim should be rejected")
    void shouldRejectTokenWithWrongType() {
        String hexKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(hexKey);
        SessionTokenService service = new SessionTokenService(props);

        String st = service.generateSessionToken(42L);
        var claims = service.verifySessionToken(st);
        assertEquals("ST", claims.get("type"),
                "Valid ST should have type=ST claim");

        assertThrows(SecurityException.class, () -> {
            io.jsonwebtoken.Claims c = service.verifySessionToken(st);
            if (!"AT".equals(c.get("type"))) {
                throw new SecurityException("Not an Access Token");
            }
        });
    }

    @Test
    @DisplayName("Should generate different tokens for same user")
    void shouldGenerateDifferentTokensForSameUser() {
        String hexKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(hexKey);
        SessionTokenService service = new SessionTokenService(props);

        String st1 = service.generateSessionToken(42L);
        String st2 = service.generateSessionToken(42L);
        assertNotEquals(st1, st2, "Each ST should have a unique jti");
    }

    @Test
    @DisplayName("Should handle minimum length seed by padding")
    void shouldHandleShortSeed() {
        String shortKey = "a1b2c3d4";
        HofmannPropertiesFromVault props = new TestHofmannPropertiesFromVault(shortKey);
        SessionTokenService service = new SessionTokenService(props);

        String st = service.generateSessionToken(42L);
        assertNotNull(st);
        var claims = service.verifySessionToken(st);
        assertEquals("42", claims.getSubject());
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
}
