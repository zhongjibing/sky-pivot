package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.common.TokenValidator;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class OpaqueTokenValidator implements TokenValidator {

    private final SessionTokenService sessionTokenService;

    public OpaqueTokenValidator(SessionTokenService sessionTokenService) {
        this.sessionTokenService = sessionTokenService;
    }

    @Override
    public Optional<Long> tryValidate(String token) {
        try {
            return Optional.of(sessionTokenService.getUserIdFromSt(token));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
