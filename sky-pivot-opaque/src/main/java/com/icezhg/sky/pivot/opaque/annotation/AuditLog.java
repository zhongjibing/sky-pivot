package com.icezhg.sky.pivot.opaque.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface AuditLog {

    String action();

    String targetType() default "";

    String level() default "INFO";

    boolean captureResult() default true;
}
