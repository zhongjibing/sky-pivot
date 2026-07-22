package com.icezhg.sky.pivot.security;

import com.icezhg.sky.pivot.dto.ApiResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import tools.jackson.databind.json.JsonMapper;

@Component
public class JwtAuthInterceptor implements HandlerInterceptor {

    private final JwtService jwtService;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public JwtAuthInterceptor(JwtService jwtService) {
        this.jwtService = jwtService;
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
        Long userId = jwtService.validateToken(token);
        request.setAttribute(JwtAuthContext.USER_ID_ATTR, userId);
        return true;
    }
}
