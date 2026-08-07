package com.icezhg.sky.pivot.opaque.aspect;

import com.icezhg.sky.pivot.opaque.annotation.AuditLog;
import com.icezhg.sky.pivot.repository.AuditLogRepository;
import com.icezhg.sky.pivot.security.JwtAuthContext;

import jakarta.servlet.http.HttpServletRequest;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;

@Aspect
@Component
public class AuditLogAspect {

    private static final Logger log = LoggerFactory.getLogger(AuditLogAspect.class);

    private final AuditLogRepository auditLogRepository;

    public AuditLogAspect(AuditLogRepository auditLogRepository) {
        this.auditLogRepository = auditLogRepository;
    }

    @Around("@annotation(auditLogAnnotation)")
    public Object around(ProceedingJoinPoint joinPoint, AuditLog auditLogAnnotation) throws Throwable {
        long startTime = System.currentTimeMillis();
        String result = "SUCCESS";
        String reason = null;

        try {
            Object returnValue = joinPoint.proceed();
            return returnValue;
        } catch (Throwable ex) {
            result = "FAILURE";
            reason = ex.getMessage();
            if (reason != null && reason.length() > 256) {
                reason = reason.substring(0, 253) + "...";
            }
            throw ex;
        } finally {
            try {
                long latencyMs = System.currentTimeMillis() - startTime;
                writeAuditLog(auditLogAnnotation, result, reason, latencyMs);
            } catch (Exception e) {
                log.warn("Failed to write audit log via AOP: {}", e.getMessage());
            }
        }
    }

    private void writeAuditLog(AuditLog annotation, String result, String reason, long latencyMs) {
        Long userId = getUserId();
        if (userId == null) {
            log.debug("No userId in request context, skipping audit log for action: {}", annotation.action());
            return;
        }

        HttpServletRequest request = getCurrentRequest();
        String deviceId = JwtAuthContext.getDeviceId();
        String action = annotation.action();
        String level = annotation.level();
        String targetType = annotation.targetType();

        if (targetType.isEmpty()) {
            targetType = null;
        }

        com.icezhg.sky.pivot.entity.AuditLog entry = new com.icezhg.sky.pivot.entity.AuditLog();
        entry.setUserId(userId);
        entry.setDeviceId(deviceId);
        entry.setAction(action);
        entry.setLevel(level);
        entry.setTargetType(targetType);
        entry.setResult(result);
        entry.setReason(reason);
        entry.setLatencyMs((int) latencyMs);
        entry.setCreatedAt(LocalDateTime.now());

        if (request != null) {
            entry.setIpAddress(getClientIp(request));
            entry.setUserAgent(request.getHeader("User-Agent"));
        }

        String requestId = MDC.get("requestId");
        if (requestId != null) {
            entry.setRequestId(requestId);
        }

        auditLogRepository.save(entry);
    }

    private Long getUserId() {
        try {
            return JwtAuthContext.getUserId();
        } catch (Exception e) {
            return null;
        }
    }

    private HttpServletRequest getCurrentRequest() {
        try {
            ServletRequestAttributes attrs =
                    (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs != null) {
                return attrs.getRequest();
            }
        } catch (Exception e) {
            log.debug("No request context available for audit log IP extraction");
        }
        return null;
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
