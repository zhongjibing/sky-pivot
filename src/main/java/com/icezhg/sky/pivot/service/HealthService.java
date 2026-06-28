package com.icezhg.sky.pivot.service;

import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class HealthService {

    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
        "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
        "letmein", "football", "shadow", "superman", "michael", "ninja",
        "mustang", "access", "thunder", "matrix", "love", "whatever",
        "summer", "winter", "spring", "autumn", "hello", "charlie",
        "donald", "password1", "password123", "admin", "root", "toor",
        "pass", "test", "guest", "master123", "changeme", "passwd"
    ));

    public HealthResult checkHealth(String password) {
        int score = 0;

        score += scoreLength(password);
        score += scoreDiversity(password);
        score += scoreCommon(password);

        String level;
        if (score <= 40) level = "WEAK";
        else if (score <= 70) level = "FAIR";
        else if (score <= 90) level = "STRONG";
        else level = "VERY_STRONG";

        return new HealthResult(Math.min(100, Math.max(0, score)), level);
    }

    private int scoreLength(String password) {
        int len = password.length();
        if (len >= 16) return 25;
        if (len >= 12) return 22;
        if (len >= 10) return 18;
        if (len >= 8) return 12;
        return 5;
    }

    private int scoreDiversity(String password) {
        int classes = 0;
        if (password.matches(".*[A-Z].*")) classes++;
        if (password.matches(".*[a-z].*")) classes++;
        if (password.matches(".*\\d.*")) classes++;
        if (password.matches(".*[^A-Za-z0-9].*")) classes++;

        return switch (classes) {
            case 4 -> 30;
            case 3 -> 22;
            case 2 -> 14;
            case 1 -> 5;
            default -> 0;
        };
    }

    private int scoreCommon(String password) {
        if (COMMON_PASSWORDS.contains(password.toLowerCase())) {
            return 0;
        }
        return 30;
    }

    public record HealthResult(int score, String level) {}
}
