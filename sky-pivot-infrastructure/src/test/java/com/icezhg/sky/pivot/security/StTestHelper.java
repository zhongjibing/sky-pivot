package com.icezhg.sky.pivot.security;

import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

final class StTestHelper {

    private static final HexFormat HEX = HexFormat.of();
    private static final String TEST_KEY_HEX =
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static PrivateKey getSigningKey() {
        try {
            byte[] seed = HEX.parseHex(TEST_KEY_HEX);
            byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
            System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
            System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePrivate(pkcs8Spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create signing key", e);
        }
    }

    static String generateValidSt() {
        PrivateKey signingKey = getSigningKey();
        Instant now = Instant.now();
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject("42")
                .claim("type", "ST")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(15 * 60)))
                .id(UUID.randomUUID().toString())
                .signWith(signingKey, Jwts.SIG.EdDSA)
                .compact();
    }

    static String generateNonStToken() {
        PrivateKey signingKey = getSigningKey();
        Instant now = Instant.now();
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject("42")
                .claim("type", "AT")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(2 * 60 * 60)))
                .id(UUID.randomUUID().toString())
                .signWith(signingKey, Jwts.SIG.EdDSA)
                .compact();
    }
}
