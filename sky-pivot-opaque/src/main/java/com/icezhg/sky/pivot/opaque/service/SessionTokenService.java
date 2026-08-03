package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.opaque.config.HofmannPropertiesFromVault;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class SessionTokenService {

    private static final Logger log = LoggerFactory.getLogger(SessionTokenService.class);
    private static final long ST_TTL_SECONDS = 15 * 60;
    private static final HexFormat HEX = HexFormat.of();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e,
        0x02, 0x01, 0x00,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x04, 0x22,
        0x04, 0x20
    };

    private static final byte[] BC_X509_HEADER = {
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    };

    private final PrivateKey signingKey;
    private final PublicKey verifyKey;
    private final RedisService redisService;

    public SessionTokenService(HofmannPropertiesFromVault propsFromVault, RedisService redisService) {
        this.redisService = redisService;
        try {
            byte[] seed = HEX.parseHex(propsFromVault.getJwtStSecretHex());
            if (seed.length < 32) {
                byte[] padded = new byte[32];
                System.arraycopy(seed, 0, padded, 0, seed.length);
                seed = padded;
            }

            Ed25519PrivateKeyParameters bcPrivateKey = new Ed25519PrivateKeyParameters(seed, 0);
            Ed25519PublicKeyParameters bcPublicKey = bcPrivateKey.generatePublicKey();

            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);

            byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
            System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
            System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
            PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
            this.signingKey = keyFactory.generatePrivate(pkcs8Spec);

            byte[] x509Bytes = new byte[BC_X509_HEADER.length + 32];
            System.arraycopy(BC_X509_HEADER, 0, x509Bytes, 0, BC_X509_HEADER.length);
            System.arraycopy(bcPublicKey.getEncoded(), 0, x509Bytes, BC_X509_HEADER.length, 32);
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(x509Bytes);
            this.verifyKey = keyFactory.generatePublic(x509Spec);

            log.info("SessionTokenService initialized with Ed25519 key");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Ed25519 key for ST signing", e);
        }
    }

    public String generateSessionToken(Long userId) {
        Instant now = Instant.now();
        return Jwts.builder()
                .header().add("alg", "EdDSA").and()
                .subject(userId.toString())
                .claim("type", "ST")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(ST_TTL_SECONDS)))
                .id(UUID.randomUUID().toString())
                .signWith(signingKey, Jwts.SIG.EdDSA)
                .compact();
    }

    public Claims verifySessionToken(String token) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(verifyKey)
                .build()
                .parseSignedClaims(token);
        Claims claims = jws.getPayload();
        if (!"ST".equals(claims.get("type"))) {
            throw new SecurityException("Not a Session Token");
        }
        String jti = claims.getId();
        if (jti != null && isBlacklisted(jti)) {
            throw new SecurityException("Session Token has been revoked");
        }
        return claims;
    }

    public Long getUserIdFromSt(String token) {
        String subject = verifySessionToken(token).getSubject();
        return Long.parseLong(subject);
    }

    public boolean isSessionToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        try {
            Claims claims = verifySessionToken(token);
            return "ST".equals(claims.get("type"));
        } catch (Exception e) {
            return false;
        }
    }

    public void revokeSt(String jti) {
        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti);
        redisService.set(blacklistKey, "revoked", Duration.ofHours(2));
        log.debug("ST jti {} added to blacklist", jti);
    }

    private boolean isBlacklisted(String jti) {
        if (redisService == null) {
            return false;
        }
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti);
        return redisService.hasKey(key);
    }
}
