package com.icezhg.sky.pivot.opaque.interceptor;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.opaque.annotation.RequireDeviceSignature;
import com.icezhg.sky.pivot.opaque.service.AccessTokenService;
import com.icezhg.sky.pivot.security.DeviceSignatureService;
import com.icezhg.sky.pivot.security.JwtAuthContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;
import tools.jackson.databind.json.JsonMapper;

@Component
public class DeviceSignatureInterceptor implements HandlerInterceptor {

    private static final Logger log = LoggerFactory.getLogger(DeviceSignatureInterceptor.class);
    private static final String DEVICE_SIGNATURE_HEADER = "X-Device-Signature";

    private final AccessTokenService accessTokenService;
    private final DeviceSignatureService deviceSignatureService;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public DeviceSignatureInterceptor(AccessTokenService accessTokenService,
                                       DeviceSignatureService deviceSignatureService) {
        this.accessTokenService = accessTokenService;
        this.deviceSignatureService = deviceSignatureService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        if (!(handler instanceof HandlerMethod handlerMethod)) {
            return true;
        }

        boolean requiresDeviceSig = handlerMethod.hasMethodAnnotation(RequireDeviceSignature.class)
                || handlerMethod.getBeanType().isAnnotationPresent(RequireDeviceSignature.class);

        if (!requiresDeviceSig) {
            return true;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.FORBIDDEN.value(),
                            "Authorization required for device-signed operations")
            ));
            return false;
        }

        String token = authHeader.substring(7);
        String deviceSignature = request.getHeader(DEVICE_SIGNATURE_HEADER);

        if (deviceSignature == null || deviceSignature.isBlank()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.FORBIDDEN.value(),
                            "Missing X-Device-Signature header for sensitive operation")
            ));
            return false;
        }

        try {
            Long userId;
            try {
                userId = JwtAuthContext.getUserId();
            } catch (IllegalStateException e) {
                try {
                    userId = accessTokenService.getUserIdFromAt(token);
                } catch (Exception ex) {
                    response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write(objectMapper.writeValueAsString(
                            ApiResponse.error(HttpStatus.FORBIDDEN.value(), "Invalid access token")
                    ));
                    return false;
                }
            }

            String deviceId = accessTokenService.getDeviceIdFromAt(token);
            String method = request.getMethod();
            String path = request.getRequestURI();

            deviceSignatureService.verifyDeviceSignature(userId, deviceId, method, path, deviceSignature);

            return true;
        } catch (SecurityException e) {
            log.warn("Device signature verification failed: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(objectMapper.writeValueAsString(
                    ApiResponse.error(HttpStatus.FORBIDDEN.value(), e.getMessage())
            ));
            return false;
        }
    }
}
