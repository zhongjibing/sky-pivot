package com.icezhg.sky.pivot.controller;

import com.icezhg.sky.pivot.dto.ApiResponse;
import com.icezhg.sky.pivot.dto.PasswordGenerateRequest;
import com.icezhg.sky.pivot.dto.PasswordGenerateResponse;
import com.icezhg.sky.pivot.dto.PasswordStrengthRequest;
import com.icezhg.sky.pivot.dto.PasswordStrengthResponse;
import com.icezhg.sky.pivot.service.HealthService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/api/utils")
public class UtilsController {

    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL = "!@#$%^&*()_+-=[]{}|;:',.<>?";

    private final SecureRandom secureRandom = new SecureRandom();
    private final HealthService healthService;

    public UtilsController(HealthService healthService) {
        this.healthService = healthService;
    }

    @PostMapping("/generate-password")
    public ApiResponse<PasswordGenerateResponse> generatePassword(
            @RequestBody PasswordGenerateRequest request) {
        if (!request.uppercase() && !request.lowercase() && !request.digits() && !request.special()) {
            return ApiResponse.error(400, "At least one character type must be selected");
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

        return ApiResponse.success(new PasswordGenerateResponse(new String(password)));
    }

    @PostMapping("/check-strength")
    public ApiResponse<PasswordStrengthResponse> checkStrength(
            @RequestBody PasswordStrengthRequest request) {
        HealthService.HealthResult result = healthService.checkHealth(request.password());
        return ApiResponse.success(new PasswordStrengthResponse(result.score(), result.level()));
    }

    private void shuffle(char[] array) {
        for (int i = array.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char temp = array[i];
            array[i] = array[j];
            array[j] = temp;
        }
    }
}
