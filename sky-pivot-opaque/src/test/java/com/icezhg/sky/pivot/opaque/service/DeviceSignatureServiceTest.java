package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.entity.Device;
import com.icezhg.sky.pivot.repository.DeviceRepository;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@DisplayName("DeviceSignatureService Tests")
class DeviceSignatureServiceTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Encoder B64E = Base64.getEncoder();
    private static final String TEST_DEVICE_KEY_HEX =
            "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
    private static final String TEST_DEVICE_ID = "device-sig-test-001";
    private static final byte[] BC_PKCS8_HEADER = {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05,
        0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    };

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private DeviceSignatureService deviceSignatureService;
    private DeviceRepository deviceRepository;
    private PrivateKey devicePrivateKey;

    @BeforeEach
    void setUp() throws Exception {
        deviceRepository = mock(DeviceRepository.class);
        deviceSignatureService = new DeviceSignatureService(deviceRepository);

        byte[] seed = HEX.parseHex(TEST_DEVICE_KEY_HEX);
        Ed25519PrivateKeyParameters bcKey = new Ed25519PrivateKeyParameters(seed, 0);
        byte[] pubKeyBytes = bcKey.generatePublicKey().getEncoded();

        byte[] pkcs8Bytes = new byte[BC_PKCS8_HEADER.length + seed.length];
        System.arraycopy(BC_PKCS8_HEADER, 0, pkcs8Bytes, 0, BC_PKCS8_HEADER.length);
        System.arraycopy(seed, 0, pkcs8Bytes, BC_PKCS8_HEADER.length, seed.length);
        PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(pkcs8Bytes);
        KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        devicePrivateKey = keyFactory.generatePrivate(pkcs8Spec);
    }

    private Device createAuthorizedDevice() {
        Device device = new Device();
        device.setUserId(1L);
        device.setDeviceId(TEST_DEVICE_ID);
        device.setDeviceName("Test Device");
        device.setDeviceType("PC");
        try {
            byte[] seed = HEX.parseHex(TEST_DEVICE_KEY_HEX);
            Ed25519PrivateKeyParameters bcKey = new Ed25519PrivateKeyParameters(seed, 0);
            byte[] pubKeyBytes = bcKey.generatePublicKey().getEncoded();
            device.setEd25519PublicKey(B64E.encodeToString(pubKeyBytes));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        device.setAuthorized(true);
        device.setRevoked(false);
        return device;
    }

    private String buildDeviceSignature(String method, String path) throws Exception {
        byte[] content = (method + path).getBytes(StandardCharsets.UTF_8);
        Signature signer = Signature.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME);
        signer.initSign(devicePrivateKey);
        signer.update(content);
        return B64E.encodeToString(signer.sign());
    }

    @Test
    @DisplayName("AC-1: Valid device signature should verify successfully")
    void shouldVerifyValidDeviceSignature() throws Exception {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String sig = buildDeviceSignature("POST", "/api/vault/items");
        assertDoesNotThrow(() ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", sig));
    }

    @Test
    @DisplayName("AC-5: Tampered device signature should fail")
    void shouldRejectTamperedSignature() throws Exception {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String sig = buildDeviceSignature("POST", "/api/vault/items");
        byte[] sigBytes = Base64.getDecoder().decode(sig);
        sigBytes[0] = (byte) (sigBytes[0] ^ 0xFF);
        String tamperedSig = B64E.encodeToString(sigBytes);

        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", tamperedSig));
    }

    @Test
    @DisplayName("AC-5: Different method/path should fail signature verification")
    void shouldRejectWrongContent() throws Exception {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        String sig = buildDeviceSignature("DELETE", "/api/vault/items/42");
        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", sig));
    }

    @Test
    @DisplayName("Missing X-Device-Signature should fail")
    void shouldFailOnMissingSignature() {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(createAuthorizedDevice()));

        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", null));
        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", ""));
    }

    @Test
    @DisplayName("Device signature from revoked device should fail")
    void shouldFailForRevokedDevice() throws Exception {
        Device revoked = createAuthorizedDevice();
        revoked.setRevoked(true);

        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(revoked));

        String sig = buildDeviceSignature("POST", "/api/vault/items");
        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", sig));
    }

    @Test
    @DisplayName("Device signature from unauthorized device should fail")
    void shouldFailForUnauthorizedDevice() throws Exception {
        Device unauth = createAuthorizedDevice();
        unauth.setAuthorized(false);

        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.of(unauth));

        String sig = buildDeviceSignature("POST", "/api/vault/items");
        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", sig));
    }

    @Test
    @DisplayName("Device not found should fail")
    void shouldFailForUnknownDevice() throws Exception {
        when(deviceRepository.findByUserIdAndDeviceId(1L, TEST_DEVICE_ID))
                .thenReturn(Optional.empty());

        String sig = buildDeviceSignature("POST", "/api/vault/items");
        assertThrows(SecurityException.class, () ->
                deviceSignatureService.verifyDeviceSignature(1L, TEST_DEVICE_ID, "POST", "/api/vault/items", sig));
    }
}
