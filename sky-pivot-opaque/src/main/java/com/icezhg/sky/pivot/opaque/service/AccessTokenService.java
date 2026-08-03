package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.common.TokenValidator;
import com.icezhg.sky.pivot.config.redis.RedisKeyPrefix;
import com.icezhg.sky.pivot.config.redis.RedisService;
import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.JsonNode;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

@Service
public class AccessTokenService implements TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(AccessTokenService.class);
    private static final long AT_TTL_SECONDS = 2 * 60 * 60;
    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private static final byte[] BC_X509_HEADER = {
        0x30, 0x2a,
        0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final DeviceRepository deviceRepository;
    private final RedisService redisService;
    private final JsonMapper jsonMapper = JsonMapper.builder().build();

    public AccessTokenService(DeviceRepository deviceRepository, RedisService redisService) {
        this.deviceRepository = deviceRepository;
        this.redisService = redisService;
    }

    public Claims verifyAccessToken(String token) {
        ParsedTokenPayload parsed = parseTokenPayload(token);

        if (!"AT".equals(parsed.type)) {
            throw new SecurityException("Not an Access Token");
        }

        if (parsed.deviceId == null || parsed.deviceId.isBlank()) {
            throw new SecurityException("AT missing device ID (did claim)");
        }

        Device device = deviceRepository.findByUserIdAndDeviceId(parsed.userId, parsed.deviceId)
                .orElseThrow(() -> new SecurityException("Device not found: " + parsed.deviceId));

        if (!Boolean.TRUE.equals(device.getAuthorized())) {
            throw new SecurityException("Device not authorized");
        }

        if (Boolean.TRUE.equals(device.getRevoked())) {
            throw new SecurityException("Device revoked");
        }

        PublicKey publicKey = parseEd25519PublicKey(device.getEd25519PublicKey());
        Claims verified = verifySignature(token, publicKey);

        String jti = verified.getId();
        if (jti != null && isBlacklisted(jti)) {
            throw new SecurityException("Access Token has been revoked");
        }

        return verified;
    }

    public Long getUserIdFromAt(String token) {
        return Long.parseLong(verifyAccessToken(token).getSubject());
    }

    public String getDeviceIdFromAt(String token) {
        return verifyAccessToken(token).get("did", String.class);
    }

    public boolean isAccessToken(String token) {
        if (token == null || token.isBlank()) {
            return false;
        }
        try {
            ParsedTokenPayload parsed = parseTokenPayload(token);
            return "AT".equals(parsed.type);
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public Optional<Long> tryValidate(String token) {
        try {
            return Optional.of(getUserIdFromAt(token));
        } catch (Exception e) {
            log.debug("AT validation failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    public void revokeAt(String jti) {
        String blacklistKey = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti);
        Duration ttl = Duration.ofSeconds(AT_TTL_SECONDS + 60);
        redisService.set(blacklistKey, "revoked", ttl);
        log.debug("AT jti {} added to blacklist", jti);
    }

    public void revokeAllForDevice(Long userId, String deviceId) {
        log.info("Device {} for user {} marked revoked — existing ATs will fail verification", deviceId, userId);
    }

    ParsedTokenPayload parseTokenPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            throw new SecurityException("Invalid JWT format");
        }
        try {
            byte[] payload = B64D.decode(parts[1]);
            String payloadJson = new String(payload, StandardCharsets.UTF_8);
            JsonNode node = jsonMapper.readTree(payloadJson);

            String type = node.has("type") ? node.get("type").asText() : null;
            Long userId = null;
            if (node.has("sub")) {
                userId = Long.parseLong(node.get("sub").asText());
            }
            String deviceId = node.has("did") ? node.get("did").asText() : null;
            String jti = node.has("jti") ? node.get("jti").asText() : null;
            long exp = node.has("exp") ? node.get("exp").asLong() : 0;
            long iat = node.has("iat") ? node.get("iat").asLong() : 0;

            if (userId == null) {
                throw new SecurityException("AT missing subject claim");
            }

            return new ParsedTokenPayload(userId, type, deviceId, jti, iat, exp);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Failed to parse AT payload", e);
        }
    }

    Claims verifySignature(String token, PublicKey publicKey) {
        Jws<Claims> jws = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token);
        return jws.getPayload();
    }

    record ParsedTokenPayload(Long userId, String type, String deviceId, String jti, long iat, long exp) {}

    PublicKey parseEd25519PublicKey(String encodedKey) {
        try {
            byte[] rawKey = decodePublicKeyBytes(encodedKey);
            byte[] x509Bytes = new byte[BC_X509_HEADER.length + rawKey.length];
            System.arraycopy(BC_X509_HEADER, 0, x509Bytes, 0, BC_X509_HEADER.length);
            System.arraycopy(rawKey, 0, x509Bytes, BC_X509_HEADER.length, rawKey.length);
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(x509Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            return keyFactory.generatePublic(x509Spec);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Failed to parse device public key", e);
        }
    }

    private byte[] decodePublicKeyBytes(String encodedKey) {
        if (encodedKey == null || encodedKey.isBlank()) {
            throw new SecurityException("Empty device public key");
        }
        try {
            return B64D.decode(encodedKey);
        } catch (IllegalArgumentException ignored) {
        }
        try {
            return HEX.parseHex(encodedKey);
        } catch (IllegalArgumentException ignored) {
        }
        throw new SecurityException("Unsupported public key encoding");
    }

    private boolean isBlacklisted(String jti) {
        if (redisService == null) {
            return false;
        }
        String key = RedisKeyPrefix.key(RedisKeyPrefix.JWT_BLACKLIST, jti);
        return redisService.hasKey(key);
    }
}
