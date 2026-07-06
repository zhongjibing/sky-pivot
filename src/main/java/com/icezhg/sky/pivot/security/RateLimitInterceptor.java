package com.icezhg.sky.pivot.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.icezhg.sky.pivot.config.properties.SecurityProperties;
import com.icezhg.sky.pivot.dto.ApiResponse;
import tools.jackson.databind.json.JsonMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.concurrent.TimeUnit;

@Component
public class RateLimitInterceptor implements HandlerInterceptor {

    private final Cache<String, Integer> rateLimitCache;
    private final int maxRequests;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public RateLimitInterceptor(SecurityProperties securityProperties) {
        this.maxRequests = securityProperties.getRateLimit();
        this.rateLimitCache = Caffeine.newBuilder()
            .expireAfterWrite(securityProperties.getRateLimitWindowSeconds(), TimeUnit.SECONDS)
            .maximumSize(100000)
            .build();
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        String userId = request.getHeader("X-User-Id");
        if (userId == null || userId.isBlank()) {
            userId = request.getRemoteAddr();
        }

        String key = userId + ":" + request.getRequestURI();
        int count = rateLimitCache.get(key, k -> 0);

        if (count >= maxRequests) {
            response.setStatus(429);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                ApiResponse.error(429, "Rate limit exceeded. Try again later.")
            ));
            return false;
        }

        rateLimitCache.put(key, count + 1);
        return true;
    }
}
