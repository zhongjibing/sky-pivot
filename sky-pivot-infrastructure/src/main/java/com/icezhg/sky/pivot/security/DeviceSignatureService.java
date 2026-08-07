package com.icezhg.sky.pivot.security;

import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;

@Service
public class DeviceSignatureService {

    private static final Logger log = LoggerFactory.getLogger(DeviceSignatureService.class);
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

    public DeviceSignatureService(DeviceRepository deviceRepository) {
        this.deviceRepository = deviceRepository;
    }

    public void verifyDeviceSignature(Long userId, String deviceId, String method, String path,
                                       String signatureBase64) {
        if (signatureBase64 == null || signatureBase64.isBlank()) {
            throw new SecurityException("Missing X-Device-Signature header");
        }

        Device device = deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new SecurityException("Device not found: " + deviceId));

        if (!Boolean.TRUE.equals(device.getAuthorized())) {
            throw new SecurityException("Device not authorized for signing");
        }

        if (Boolean.TRUE.equals(device.getRevoked())) {
            throw new SecurityException("Device revoked, signature rejected");
        }

        try {
            byte[] rawKey = decodePublicKeyBytes(device.getEd25519PublicKey());
            byte[] x509Bytes = new byte[BC_X509_HEADER.length + rawKey.length];
            System.arraycopy(BC_X509_HEADER, 0, x509Bytes, 0, BC_X509_HEADER.length);
            System.arraycopy(rawKey, 0, x509Bytes, BC_X509_HEADER.length, rawKey.length);
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(x509Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey publicKey = keyFactory.generatePublic(x509Spec);

            byte[] signature = B64D.decode(signatureBase64);
            byte[] signedContent = (method + path).getBytes(StandardCharsets.UTF_8);

            Signature verifier = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(signedContent);

            if (!verifier.verify(signature)) {
                throw new SecurityException("Device signature verification failed");
            }

            log.debug("Device signature verified for device: {} on {} {}", deviceId, method, path);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Device signature verification error: " + e.getMessage(), e);
        }
    }

    public void verifyContentSignature(Long userId, String deviceId, byte[] content, String signatureBase64) {
        if (signatureBase64 == null || signatureBase64.isBlank()) {
            throw new SecurityException("Missing device signature");
        }

        Device device = deviceRepository.findByUserIdAndDeviceId(userId, deviceId)
                .orElseThrow(() -> new SecurityException("Device not found: " + deviceId));

        if (!Boolean.TRUE.equals(device.getAuthorized())) {
            throw new SecurityException("Device not authorized for signing");
        }

        if (Boolean.TRUE.equals(device.getRevoked())) {
            throw new SecurityException("Device revoked, signature rejected");
        }

        try {
            byte[] rawKey = decodePublicKeyBytes(device.getEd25519PublicKey());
            byte[] x509Bytes = new byte[BC_X509_HEADER.length + rawKey.length];
            System.arraycopy(BC_X509_HEADER, 0, x509Bytes, 0, BC_X509_HEADER.length);
            System.arraycopy(rawKey, 0, x509Bytes, BC_X509_HEADER.length, rawKey.length);
            X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(x509Bytes);
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            PublicKey publicKey = keyFactory.generatePublic(x509Spec);

            byte[] signature = B64D.decode(signatureBase64);

            Signature verifier = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
            verifier.initVerify(publicKey);
            verifier.update(content);

            if (!verifier.verify(signature)) {
                throw new SecurityException("Device content signature verification failed");
            }

            log.debug("Device content signature verified for device: {}", deviceId);
        } catch (SecurityException e) {
            throw e;
        } catch (Exception e) {
            throw new SecurityException("Device content signature verification error: " + e.getMessage(), e);
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
}
