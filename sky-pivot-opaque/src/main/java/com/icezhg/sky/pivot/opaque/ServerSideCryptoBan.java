package com.icezhg.sky.pivot.opaque;

public final class ServerSideCryptoBan {

    public static final String[] BANNED_IMPORTS = {
            "javax.crypto.Cipher",
            "javax.crypto.SecretKey",
            "javax.crypto.spec.SecretKeySpec",
            "javax.crypto.spec.IvParameterSpec",
            "javax.crypto.spec.PBEKeySpec",
            "javax.crypto.SecretKeyFactory",
            "javax.crypto.spec.GCMParameterSpec",
            "org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder",
            "org.springframework.security.crypto.password.PasswordEncoder",
            "com.icezhg.sky.pivot.CryptoService",
    };

    public static final String[] BANNED_METHOD_PATTERNS = {
            "PBKDF2",
            "Argon2id",
            "Cipher.getInstance",
            "SecretKeyFactory.getInstance",
            "BCryptPasswordEncoder",
    };

    public static final String[] BANNED_CONFIG_PATTERNS = {
            "at.signing",
            "at.secret",
            "at.private-key",
            "access-token.signing",
            "access-token.secret",
            "access-token.private-key",
            "accesstoken.signing",
            "accesstoken.secret",
    };

    private ServerSideCryptoBan() {
    }
}
