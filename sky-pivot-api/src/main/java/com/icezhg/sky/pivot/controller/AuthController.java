package com.icezhg.sky.pivot.controller;

import com.codeheadsystems.hofmann.model.opaque.*;
import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.opaque.dto.OpaqueRegisterStartRequest;
import com.icezhg.sky.pivot.opaque.dto.OpaqueRegisterStartResponse;
import com.icezhg.sky.pivot.opaque.dto.OpaqueRegisterFinishRequest;
import com.icezhg.sky.pivot.opaque.dto.OpaqueLoginStartRequest;
import com.icezhg.sky.pivot.opaque.dto.OpaqueLoginStartResponse;
import com.icezhg.sky.pivot.opaque.dto.OpaqueLoginFinishRequest;
import com.icezhg.sky.pivot.opaque.dto.OpaqueLoginFinishResponse;
import com.icezhg.sky.pivot.opaque.dto.OpaqueCredentialUpdateRequest;
import com.icezhg.sky.pivot.opaque.service.OpaqueAuthService;
import com.icezhg.sky.pivot.opaque.service.OpaqueAuthService.LoginFinishResponse;
import com.icezhg.sky.pivot.opaque.service.RateLimitService;
import com.icezhg.sky.pivot.opaque.service.SessionTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth/opaque")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private final OpaqueAuthService opaqueAuthService;
    private final RateLimitService rateLimitService;
    private final SessionTokenService sessionTokenService;

    public AuthController(OpaqueAuthService opaqueAuthService,
                          RateLimitService rateLimitService,
                          SessionTokenService sessionTokenService) {
        this.opaqueAuthService = opaqueAuthService;
        this.rateLimitService = rateLimitService;
        this.sessionTokenService = sessionTokenService;
    }

    @PostMapping("/register-start")
    public ResponseEntity<ApiResponse<OpaqueRegisterStartResponse>> registerStart(
            @Valid @RequestBody OpaqueRegisterStartRequest request) {

        RegistrationStartRequest hofmannRequest = new RegistrationStartRequest(
                java.util.Base64.getDecoder().decode(request.credentialIdentifierBase64()),
                new com.codeheadsystems.rfc.opaque.model.RegistrationRequest(
                        java.util.Base64.getDecoder().decode(request.blindedElementBase64()))
        );

        RegistrationStartResponse hofmannResponse = opaqueAuthService.handleRegisterStart(hofmannRequest);
        OpaqueRegisterStartResponse response = new OpaqueRegisterStartResponse(
                hofmannResponse.evaluatedElementBase64(),
                hofmannResponse.serverPublicKeyBase64()
        );
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/register-finish")
    public ResponseEntity<ApiResponse<Void>> registerFinish(
            @Valid @RequestBody OpaqueRegisterFinishRequest request) {

        RegistrationFinishRequest hofmannRequest = new RegistrationFinishRequest(
                java.util.Base64.getDecoder().decode(request.credentialIdentifierBase64()),
                new com.codeheadsystems.rfc.opaque.model.RegistrationRecord(
                        java.util.Base64.getDecoder().decode(request.clientPublicKeyBase64()),
                        java.util.Base64.getDecoder().decode(request.maskingKeyBase64()),
                        new com.codeheadsystems.rfc.opaque.model.Envelope(
                                java.util.Base64.getDecoder().decode(request.envelopeNonceBase64()),
                                java.util.Base64.getDecoder().decode(request.authTagBase64())
                        ))
        );

        opaqueAuthService.handleRegisterFinish(hofmannRequest);
        return ResponseEntity.ok(ApiResponse.success());
    }

    @PostMapping("/login-start")
    public ResponseEntity<ApiResponse<OpaqueLoginStartResponse>> loginStart(
            @Valid @RequestBody OpaqueLoginStartRequest request,
            HttpServletRequest servletRequest) {

        String ip = getClientIp(servletRequest);
        if (!rateLimitService.isLoginStartAllowed(ip)) {
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(ApiResponse.error("429", "Too many login attempts. Please try again later."));
        }

        AuthStartRequest hofmannRequest = new AuthStartRequest(
                java.util.Base64.getDecoder().decode(request.credentialIdentifierBase64()),
                new com.codeheadsystems.rfc.opaque.model.KE1(
                        new com.codeheadsystems.rfc.opaque.model.CredentialRequest(
                                java.util.Base64.getDecoder().decode(request.blindedElementBase64())),
                        java.util.Base64.getDecoder().decode(request.clientNonceBase64()),
                        java.util.Base64.getDecoder().decode(request.clientAkePublicKeyBase64()))
        );

        AuthStartResponse hofmannResponse = opaqueAuthService.handleLoginStart(hofmannRequest);
        OpaqueLoginStartResponse response = new OpaqueLoginStartResponse(
                hofmannResponse.sessionToken(),
                hofmannResponse.evaluatedElementBase64(),
                hofmannResponse.maskingNonceBase64(),
                hofmannResponse.maskedResponseBase64(),
                hofmannResponse.serverNonceBase64(),
                hofmannResponse.serverAkePublicKeyBase64(),
                hofmannResponse.serverMacBase64()
        );
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/login-finish")
    public ResponseEntity<ApiResponse<OpaqueLoginFinishResponse>> loginFinish(
            @Valid @RequestBody OpaqueLoginFinishRequest request) {

        AuthFinishRequest hofmannRequest = new AuthFinishRequest(
                request.sessionToken(),
                new com.codeheadsystems.rfc.opaque.model.KE3(
                        java.util.Base64.getDecoder().decode(request.clientMacBase64()))
        );

        LoginFinishResponse result = opaqueAuthService.handleLoginFinish(
                hofmannRequest, request.credentialIdentifierBase64());
        OpaqueLoginFinishResponse response = new OpaqueLoginFinishResponse(
                result.sessionToken(), result.userId()
        );
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/credential-update")
    public ResponseEntity<ApiResponse<Void>> credentialUpdate(
            @Valid @RequestBody OpaqueCredentialUpdateRequest request,
            HttpServletRequest servletRequest) {

        String authHeader = servletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);
        try {
            sessionTokenService.getUserIdFromSt(token);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired session token"));
        }

        opaqueAuthService.handleCredentialUpdate(request);
        return ResponseEntity.ok(ApiResponse.success());
    }

    @PostMapping("/token-exchange")
    public ResponseEntity<ApiResponse<TokenExchangeResponse>> tokenExchange(
            HttpServletRequest servletRequest) {

        String authHeader = servletRequest.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Missing or invalid Authorization header"));
        }

        String token = authHeader.substring(7);
        try {
            var claims = sessionTokenService.verifySessionToken(token);
            Long userId = Long.parseLong(claims.getSubject());
            log.info("ST exchanged for userId: {}, jti: {}", userId, claims.getId());
            return ResponseEntity.ok(ApiResponse.success(
                    new TokenExchangeResponse(userId.toString(), claims.getId(), claims.getExpiration().toString())));
        } catch (SecurityException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(ApiResponse.error("403", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ApiResponse.error("401", "Invalid or expired session token"));
        }
    }

    public record TokenExchangeResponse(String userId, String jti, String expiresAt) {}

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
