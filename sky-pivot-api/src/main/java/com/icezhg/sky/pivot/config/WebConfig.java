package com.icezhg.sky.pivot.config;

import com.icezhg.sky.pivot.opaque.interceptor.DeviceSignatureInterceptor;
import com.icezhg.sky.pivot.security.JwtAuthInterceptor;
import com.icezhg.sky.pivot.security.RateLimitInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    private final RateLimitInterceptor rateLimitInterceptor;
    private final JwtAuthInterceptor jwtAuthInterceptor;
    private final DeviceSignatureInterceptor deviceSignatureInterceptor;

    public WebConfig(RateLimitInterceptor rateLimitInterceptor,
                     JwtAuthInterceptor jwtAuthInterceptor,
                     DeviceSignatureInterceptor deviceSignatureInterceptor) {
        this.rateLimitInterceptor = rateLimitInterceptor;
        this.jwtAuthInterceptor = jwtAuthInterceptor;
        this.deviceSignatureInterceptor = deviceSignatureInterceptor;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOriginPatterns("*")
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .allowCredentials(true)
            .maxAge(3600);
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(jwtAuthInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(
                        "/api/miniapp/login",
                        "/api/pc/login/qrcode",
                        "/api/pc/login/status/**",
                        "/api/pc/login/confirm",
                        "/api/auth/**",
                        "/api/devices/activate",
                        "/api/devices/emergency-auth/**",
                        "/api/devices/authorize/**"
                );
        registry.addInterceptor(deviceSignatureInterceptor)
                .addPathPatterns("/api/**")
                .excludePathPatterns(
                        "/api/auth/**",
                        "/api/miniapp/**",
                        "/api/pc/**",
                        "/api/actuator/**",
                        "/api/devices/activate",
                        "/api/devices/emergency-auth/**",
                        "/api/devices/authorize/**",
                        "/api/devices"
                );
        registry.addInterceptor(rateLimitInterceptor)
                .addPathPatterns("/api/**");
    }
}
