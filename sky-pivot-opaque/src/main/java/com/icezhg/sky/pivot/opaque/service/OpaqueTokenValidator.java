package com.icezhg.sky.pivot.opaque.service;

import com.icezhg.sky.pivot.common.TokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class OpaqueTokenValidator implements TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(OpaqueTokenValidator.class);

    private final SessionTokenService sessionTokenService;

    public OpaqueTokenValidator(SessionTokenService sessionTokenService) {
        this.sessionTokenService = sessionTokenService;
    }

    @Override
    public Optional<Long> tryValidate(String token) {
        if (sessionTokenService.isSessionToken(token)) {
            log.debug("ST rejected: Session Tokens are only valid for token exchange, not general API access");
            return Optional.empty();
        }
        return Optional.empty();
    }
}
