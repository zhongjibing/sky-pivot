package com.icezhg.sky.pivot.config;

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

    public WebConfig(RateLimitInterceptor rateLimitInterceptor, JwtAuthInterceptor jwtAuthInterceptor) {
        this.rateLimitInterceptor = rateLimitInterceptor;
        this.jwtAuthInterceptor = jwtAuthInterceptor;
    }

    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins(
                "http://localhost:8080"
            )
            .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
            .allowedHeaders("*")
            .exposedHeaders("X-Token")
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
                        "/api/pc/login/confirm"
                );
        registry.addInterceptor(rateLimitInterceptor)
            .addPathPatterns("/api/**");
    }
}
