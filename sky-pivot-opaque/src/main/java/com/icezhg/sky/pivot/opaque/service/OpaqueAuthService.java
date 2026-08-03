package com.icezhg.sky.pivot.opaque.service;

import com.codeheadsystems.hofmann.model.opaque.*;
import com.codeheadsystems.hofmann.server.manager.HofmannOpaqueServerManager;
import com.codeheadsystems.hofmann.server.store.CredentialStore;
import com.codeheadsystems.rfc.opaque.model.Envelope;
import com.codeheadsystems.rfc.opaque.model.RegistrationRecord;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.opaque.dto.OpaqueCredentialUpdateRequest;
import com.icezhg.sky.pivot.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Base64;
import java.util.Optional;

@Service
public class OpaqueAuthService {

    private static final Logger log = LoggerFactory.getLogger(OpaqueAuthService.class);
    private static final Base64.Encoder B64 = Base64.getEncoder();
    private static final Base64.Decoder B64D = Base64.getDecoder();

    private final HofmannOpaqueServerManager opaqueServerManager;
    private final CredentialStore credentialStore;
    private final UserRepository userRepository;
    private final SessionTokenService sessionTokenService;

    public OpaqueAuthService(HofmannOpaqueServerManager opaqueServerManager,
                             CredentialStore credentialStore,
                             UserRepository userRepository,
                             SessionTokenService sessionTokenService) {
        this.opaqueServerManager = opaqueServerManager;
        this.credentialStore = credentialStore;
        this.userRepository = userRepository;
        this.sessionTokenService = sessionTokenService;
    }

    public RegistrationStartResponse handleRegisterStart(RegistrationStartRequest request) {
        try {
            return opaqueServerManager.registrationStart(request);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid registration start request", e);
            throw e;
        }
    }

    @Transactional
    public void handleRegisterFinish(RegistrationFinishRequest request) {
        try {
            String credId = request.credentialIdentifierBase64();
            byte[] credIdBytes = B64D.decode(credId);

            Optional<User> existing = userRepository.findByCredentialIdentifier(credId);
            if (existing.isPresent() && existing.get().getOpaqueServerRecord() != null
                    && existing.get().getOpaqueServerRecord().length > 0) {
                throw new IllegalArgumentException("User already registered: " + credId);
            }

            opaqueServerManager.registrationFinish(request);
            log.info("OPAQUE registration completed for credential: {}", credId);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid registration finish request", e);
            throw e;
        }
    }

    public AuthStartResponse handleLoginStart(AuthStartRequest request) {
        try {
            String credId = request.credentialIdentifierBase64();
            Optional<User> user = userRepository.findByCredentialIdentifier(credId);
            if (user.isEmpty()) {
                throw new IllegalArgumentException("User not found");
            }
            if (user.get().getStatus() != null && user.get().getStatus() == 2) {
                throw new IllegalArgumentException("Account has been deleted");
            }
            if (user.get().getStatus() != null && user.get().getStatus() == 1) {
                throw new IllegalArgumentException("Account has been disabled");
            }
            return opaqueServerManager.authStart(request);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid login start request", e);
            throw e;
        }
    }

    @Transactional
    public LoginFinishResponse handleLoginFinish(AuthFinishRequest request, String credentialIdentifierBase64) {
        try {
            AuthFinishResponse authFinishResponse = opaqueServerManager.authFinish(request);

            User user = userRepository.findByCredentialIdentifier(credentialIdentifierBase64)
                    .orElseThrow(() -> new SecurityException("User not found for session"));

            String st = sessionTokenService.generateSessionToken(user.getId());
            String sessionKeyBase64 = authFinishResponse.sessionKeyBase64();
            log.info("OPAQUE login completed for userId: {}, credential: {}", user.getId(), credentialIdentifierBase64);
            return new LoginFinishResponse(st, user.getId().toString(), sessionKeyBase64);
        } catch (Exception e) {
            log.debug("Invalid login finish request", e);
            throw e;
        }
    }

    public void handleRegistrationDelete(String credentialIdentifierBase64) {
        byte[] credIdBytes = B64D.decode(credentialIdentifierBase64);
        opaqueServerManager.registrationDelete(
                new RegistrationDeleteRequest(credIdBytes), "");
        log.info("OPAQUE registration deleted for credential: {}", credentialIdentifierBase64);
    }

    @Transactional
    public void handleCredentialUpdate(OpaqueCredentialUpdateRequest request) {
        try {
            String credId = request.credentialIdentifierBase64();
            byte[] credIdBytes = B64D.decode(credId);

            User user = userRepository.findByCredentialIdentifier(credId)
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));

            credentialStore.delete(credIdBytes);

            RegistrationRecord newRecord = new RegistrationRecord(
                    B64D.decode(request.clientPublicKeyBase64()),
                    B64D.decode(request.maskingKeyBase64()),
                    new Envelope(
                            B64D.decode(request.envelopeNonceBase64()),
                            B64D.decode(request.authTagBase64()))
            );

            RegistrationFinishRequest finishRequest = new RegistrationFinishRequest(credIdBytes, newRecord);
            opaqueServerManager.registrationFinish(finishRequest);
            log.info("OPAQUE credential updated for userId: {}, credential: {}", user.getId(), credId);
        } catch (IllegalArgumentException e) {
            log.debug("Invalid credential update request", e);
            throw e;
        }
    }

    public record LoginFinishResponse(String sessionToken, String userId, String sessionKeyBase64) {
    }
}
