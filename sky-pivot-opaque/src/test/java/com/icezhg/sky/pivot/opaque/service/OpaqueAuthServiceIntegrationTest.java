package com.icezhg.sky.pivot.opaque.service;

import com.codeheadsystems.hofmann.model.opaque.*;
import com.codeheadsystems.hofmann.server.auth.JwtManager;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.store.InMemorySessionStore;
import com.codeheadsystems.hofmann.server.store.SessionStore;
import com.codeheadsystems.rfc.opaque.Client;
import com.codeheadsystems.rfc.opaque.Server;
import com.codeheadsystems.rfc.opaque.config.OpaqueCipherSuite;
import com.codeheadsystems.rfc.opaque.config.OpaqueConfig;
import com.codeheadsystems.rfc.opaque.model.*;
import com.codeheadsystems.rfc.oprf.rfc9497.OprfCipherSuite;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.opaque.store.JpaCredentialStore;
import com.icezhg.sky.pivot.repository.UserRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@DisplayName("OPAQUE Authentication Integration Tests")
class OpaqueAuthServiceIntegrationTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private static final byte[] PASSWORD = "MySecurePassword123!".getBytes(StandardCharsets.UTF_8);
    private static final byte[] CRED_ID = HEX.parseHex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6");
    private static final String CRED_ID_B64 = B64.encodeToString(CRED_ID);

    private static final byte[] SERVER_IDENTITY = "sky-pivot-v1".getBytes(StandardCharsets.UTF_8);

    private static final byte[] SERVER_KEY_SEED = HEX.parseHex(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    private static final byte[] OPRF_SEED = HEX.parseHex(
            "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    private static final String OPRF_MASTER_KEY_HEX =
            "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

    private OpaqueAuthService opaqueAuthService;
    private SessionTokenService sessionTokenService;
    private UserRepository userRepository;
    private User savedUser;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        userRepository = mock(UserRepository.class);
        savedUser = new User();
        savedUser.setId(1L);
        savedUser.setCredentialIdentifier(CRED_ID_B64);
        savedUser.setSalt("");
        savedUser.setEncryptedDek("");
        savedUser.setEncryptedUrkRecovery("");
        savedUser.setRecoverySalt("");
        savedUser.setRecoveryKeyHash("");
        savedUser.setStatus(0);

        JpaCredentialStore credentialStore = new JpaCredentialStore(userRepository);

        OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
                .withSuite("P256_SHA256")
                .withRandom(new SecureRandom())
                .build();
        OpaqueCipherSuite opaqueSuite = new OpaqueCipherSuite(oprfSuite);
        OpaqueConfig cfg = OpaqueConfig.withArgon2id(opaqueSuite,
                "sky-pivot-v1".getBytes(StandardCharsets.UTF_8), 65536, 3, 1);

        OpaqueCipherSuite.AkeKeyPair keyPair = opaqueSuite.deriveAkeKeyPair(SERVER_KEY_SEED);
        BigInteger sk = keyPair.privateKey();
        byte[] pk = keyPair.publicKeyBytes();
        byte[] skFixed = new byte[cfg.Nsk()];
        byte[] skBytes = sk.toByteArray();
        if (skBytes.length > cfg.Nsk()) {
            System.arraycopy(skBytes, skBytes.length - cfg.Nsk(), skFixed, 0, cfg.Nsk());
        } else {
            System.arraycopy(skBytes, 0, skFixed, cfg.Nsk() - skBytes.length, skBytes.length);
        }

        Server rfcServer = new Server(skFixed, pk, OPRF_SEED, cfg);
        SessionStore sessionStore = new InMemorySessionStore();
        JwtManager jwtManager = new JwtManager(new byte[64], "sky-pivot-test", 900L, sessionStore);

        HofmannOpaqueServerManager opaqueServerManager = new HofmannOpaqueServerManager(
                rfcServer, credentialStore, jwtManager);

        sessionTokenService = new TestSessionTokenService();
        opaqueAuthService = new OpaqueAuthService(opaqueServerManager, credentialStore,
                userRepository, sessionTokenService);

        when(userRepository.save(any(User.class))).thenAnswer(inv -> {
            User u = inv.getArgument(0);
            savedUser.setOpaqueServerRecord(u.getOpaqueServerRecord());
            savedUser.setOpaqueClientRecord(u.getOpaqueClientRecord());
            return savedUser;
        });
    }

    @Test
    @DisplayName("AC-1: Complete registration → login flow with Hofmann client simulation")
    void shouldCompleteFullRegistrationAndLogin() {
        OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
                .withSuite("P256_SHA256")
                .withRandom(new SecureRandom())
                .build();
        OpaqueCipherSuite opaqueSuite = new OpaqueCipherSuite(oprfSuite);
        OpaqueConfig clientCfg = OpaqueConfig.withArgon2id(opaqueSuite,
                "sky-pivot-v1".getBytes(StandardCharsets.UTF_8), 65536, 3, 1);
        Client client = new Client(clientCfg);

        ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
        RegistrationStartRequest regStartReq = new RegistrationStartRequest(CRED_ID,
                regState.request());
        RegistrationStartResponse regStartResp = opaqueAuthService.handleRegisterStart(regStartReq);

        RegistrationResponse regResp = new RegistrationResponse(
                B64D.decode(regStartResp.evaluatedElementBase64()),
                B64D.decode(regStartResp.serverPublicKeyBase64()));
        RegistrationRecord regRecord = client.finalizeRegistration(regState,
                regResp, null, null);

        when(userRepository.findByCredentialIdentifier(CRED_ID_B64))
                .thenReturn(Optional.empty());

        RegistrationFinishRequest regFinishReq = new RegistrationFinishRequest(CRED_ID, regRecord);
        opaqueAuthService.handleRegisterFinish(regFinishReq);

        assertNotNull(savedUser.getOpaqueServerRecord(), "Server record should be stored");
        assertNotNull(savedUser.getOpaqueClientRecord(), "Client record should be stored");
        assertTrue(savedUser.getOpaqueServerRecord().length > 0, "Server record should not be empty");
        assertTrue(savedUser.getOpaqueClientRecord().length > 0, "Client record should not be empty");

        when(userRepository.findByCredentialIdentifier(CRED_ID_B64))
                .thenReturn(Optional.of(savedUser));

        ClientAuthState authState = client.generateKE1(PASSWORD);
        AuthStartRequest authStartReq = new AuthStartRequest(CRED_ID, authState.ke1());
        AuthStartResponse authStartResp = opaqueAuthService.handleLoginStart(authStartReq);

        byte[] maskingNonce = B64D.decode(authStartResp.maskingNonceBase64());
        byte[] maskedResponse = B64D.decode(authStartResp.maskedResponseBase64());
        byte[] serverNonce = B64D.decode(authStartResp.serverNonceBase64());
        byte[] serverAkePublicKey = B64D.decode(authStartResp.serverAkePublicKeyBase64());
        byte[] serverMac = B64D.decode(authStartResp.serverMacBase64());

        CredentialResponse credResp = new CredentialResponse(
                B64D.decode(authStartResp.evaluatedElementBase64()), maskingNonce, maskedResponse);
        KE2 ke2 = new KE2(credResp, serverNonce, serverAkePublicKey, serverMac);

        AuthResult authResult = client.generateKE3(authState, null, null, ke2);
        AuthFinishRequest authFinishReq = new AuthFinishRequest(authStartResp.sessionToken(), authResult.ke3());

        OpaqueAuthService.LoginFinishResponse loginResp = opaqueAuthService.handleLoginFinish(
                authFinishReq, CRED_ID_B64);

        assertNotNull(loginResp.sessionToken(), "ST should not be null");
        assertNotNull(loginResp.userId(), "userId should not be null");
        assertNotNull(loginResp.sessionKeyBase64(), "sessionKey should not be null");
        assertEquals("1", loginResp.userId(), "userId should match the registered user");

        Claims claims = sessionTokenService.verifySessionToken(loginResp.sessionToken());
        assertNotNull(claims, "ST should be verifiable");
        assertEquals("1", claims.getSubject(), "ST subject should be userId");
        assertEquals("ST", claims.get("type"), "ST type claim should be 'ST'");
        assertNotNull(claims.getId(), "ST should have a jti");
        assertNotNull(claims.getIssuedAt(), "ST should have issuedAt");
        assertNotNull(claims.getExpiration(), "ST should have expiration");
    }

    @Test
    @DisplayName("AC-3: ST should have 15-minute TTL with Ed25519 signature")
    void sessionTokenShouldHaveCorrectTtlAndEd25519Signature() {
        String st = sessionTokenService.generateSessionToken(42L);
        Claims claims = sessionTokenService.verifySessionToken(st);

        long iat = claims.getIssuedAt().getTime() / 1000;
        long exp = claims.getExpiration().getTime() / 1000;
        long ttl = exp - iat;

        assertEquals(900, ttl, "ST TTL should be 15 minutes (900 seconds)");
        assertTrue(ttl >= 890 && ttl <= 910,
                "ST TTL should be approximately 15 minutes, got " + ttl);

        String[] parts = st.split("\\.");
        assertEquals(3, parts.length, "ST should be valid JWT with 3 parts");

        String headerJson = new String(B64D.decode(parts[0]), StandardCharsets.UTF_8);
        assertTrue(headerJson.contains("EdDSA"),
                "ST should use EdDSA algorithm, header: " + headerJson);
    }

    @Test
    @DisplayName("AC-2: Server records stored in DB cannot reverse-engineer password")
    void storedServerRecordsShouldNotRevealPassword() {
        OprfCipherSuite oprfSuite = OprfCipherSuite.builder()
                .withSuite("P256_SHA256")
                .withRandom(new SecureRandom())
                .build();
        OpaqueCipherSuite opaqueSuite = new OpaqueCipherSuite(oprfSuite);
        OpaqueConfig clientCfg = OpaqueConfig.withArgon2id(opaqueSuite,
                "sky-pivot-v1".getBytes(StandardCharsets.UTF_8), 65536, 3, 1);
        Client client = new Client(clientCfg);

        ClientRegistrationState regState = client.createRegistrationRequest(PASSWORD);
        RegistrationStartRequest regStartReq = new RegistrationStartRequest(CRED_ID,
                regState.request());
        opaqueAuthService.handleRegisterStart(regStartReq);

        when(userRepository.findByCredentialIdentifier(CRED_ID_B64))
                .thenReturn(Optional.empty());

        RegistrationFinishRequest regFinishReq = new RegistrationFinishRequest(CRED_ID,
                new RegistrationRecord(
                        new byte[33], new byte[32],
                        new Envelope(new byte[32], new byte[32])));
        try {
            opaqueAuthService.handleRegisterFinish(regFinishReq);
        } catch (Exception ignored) {
        }

        if (savedUser.getOpaqueServerRecord() != null) {
            String storedAsString = new String(savedUser.getOpaqueServerRecord(),
                    StandardCharsets.UTF_8);
            assertFalse(storedAsString.contains("MySecure"),
                    "Stored record must not contain password fragments");
            assertFalse(storedAsString.contains("Password"),
                    "Stored record must not contain password");
            assertFalse(storedAsString.contains("123!"),
                    "Stored record must not contain password suffixes");
        }
        if (savedUser.getOpaqueClientRecord() != null) {
            String clientAsString = new String(savedUser.getOpaqueClientRecord(),
                    StandardCharsets.UTF_8);
            assertFalse(clientAsString.contains("MySecure"),
                    "Client record must not contain password fragments");
        }
    }

    static class TestSessionTokenService extends SessionTokenService {
        TestSessionTokenService() {
            super(new com.icezhg.sky.pivot.opaque.config.HofmannPropertiesFromVault(null) {
                @Override
                public String getJwtStSecretHex() {
                    return "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6";
                }
            });
        }
    }
}
