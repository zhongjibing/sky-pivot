package com.icezhg.sky.pivot.security;

import com.icezhg.sky.pivot.common.TokenValidator;
import com.icezhg.sky.pivot.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

@Component
public class JwtAuthInterceptor implements HandlerInterceptor {

    private static final String TOKEN_TYPE_ST = "\"type\":\"ST\"";
    private static final String TOKEN_TYPE_ST_ALT = "\"type\": \"ST\"";

    private final List<TokenValidator> tokenValidators;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public JwtAuthInterceptor(List<TokenValidator> tokenValidators) {
        this.tokenValidators = tokenValidators;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Missing or invalid Authorization header")
            ));
            return false;
        }

        String token = authHeader.substring(7);

        if (token.isBlank()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Missing or invalid Authorization header")
            ));
            return false;
        }

        if (isSessionTokenPayload(token)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.FORBIDDEN.value(),
                            "Session Token is only valid for token exchange, not general API access")
            ));
            return false;
        }

        Optional<Long> userId = tokenValidators.stream()
                .map(v -> v.tryValidate(token))
                .filter(Optional::isPresent)
                .map(Optional::get)
                .findFirst();

        if (userId.isEmpty()) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.UNAUTHORIZED.value(), "Invalid or expired token")
            ));
            return false;
        }

        request.setAttribute(JwtAuthContext.USER_ID_ATTR, userId.get());
        return true;
    }

    private boolean isSessionTokenPayload(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(parts[1]);
            String payload = new String(decoded, StandardCharsets.UTF_8);
            return payload.contains(TOKEN_TYPE_ST) || payload.contains(TOKEN_TYPE_ST_ALT);
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
