package com.icezhg.sky.pivot.security;

import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

public final class JwtAuthContext {

    static final String USER_ID_ATTR = "jwt_auth_user_id";

    public static Long getUserId() {
        RequestAttributes attrs = RequestContextHolder.getRequestAttributes();
        if (attrs == null) {
            throw new IllegalStateException("No request context available");
        }
        if (attrs instanceof ServletRequestAttributes sattributes) {
            return (Long) sattributes.getRequest().getAttribute(USER_ID_ATTR);
        }

        throw new IllegalStateException("No servlet request available in current context");
    }

    private JwtAuthContext() {
    }
}
