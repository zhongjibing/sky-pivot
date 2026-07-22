package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.PasswordGenerateRequest;
import com.icezhg.sky.pivot.dto.PasswordGenerateResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
public class UtilsService {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>?";

    private static final Set<String> COMMON_PASSWORDS = new HashSet<>(Arrays.asList(
        "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
        "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
        "letmein", "football", "shadow", "superman", "michael", "ninja",
        "mustang", "access", "thunder", "matrix", "love", "whatever",
        "summer", "winter", "spring", "autumn", "hello", "charlie",
        "donald", "password1", "password123", "admin", "root", "toor",
        "pass", "test", "guest", "master123", "changeme", "passwd"
    ));

    private final SecureRandom secureRandom = new SecureRandom();

    public PasswordGenerateResponse generatePassword(PasswordGenerateRequest request) {
        if (!request.uppercase() && !request.lowercase() && !request.digits() && !request.special()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one character type must be selected");
        }

        StringBuilder charPool = new StringBuilder();
        List<Character> required = new ArrayList<>();

        if (request.uppercase()) {
            charPool.append(UPPERCASE);
            required.add(UPPERCASE.charAt(secureRandom.nextInt(UPPERCASE.length())));
        }
        if (request.lowercase()) {
            charPool.append(LOWERCASE);
            required.add(LOWERCASE.charAt(secureRandom.nextInt(LOWERCASE.length())));
        }
        if (request.digits()) {
            charPool.append(DIGITS);
            required.add(DIGITS.charAt(secureRandom.nextInt(DIGITS.length())));
        }
        if (request.special()) {
            charPool.append(SPECIAL);
            required.add(SPECIAL.charAt(secureRandom.nextInt(SPECIAL.length())));
        }

        int length = Math.max(request.length(), required.size());
        char[] password = new char[length];

        for (int i = 0; i < required.size(); i++) {
            password[i] = required.get(i);
        }

        for (int i = required.size(); i < length; i++) {
            password[i] = charPool.charAt(secureRandom.nextInt(charPool.length()));
        }

        shuffle(password);

        return new PasswordGenerateResponse(new String(password));
    }

    private void shuffle(char[] array) {
        for (int i = array.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }

    public StrengthResult checkStrength(String password) {
        int score = 0;

        score += scoreLength(password);
        score += scoreDiversity(password);
        score += scoreCommon(password);

        String level;
        if (score <= 40) level = "WEAK";
        else if (score <= 70) level = "FAIR";
        else if (score <= 90) level = "STRONG";
        else level = "VERY_STRONG";

        return new StrengthResult(Math.min(100, Math.max(0, score)), level);
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

    public record StrengthResult(int score, String level) {}
}
