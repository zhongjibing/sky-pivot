package com.icezhg.sky.pivot.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HealthServiceTest {

    private final HealthService healthService = new HealthService();

    @Test
    void weakPassword_shortAndCommon() {
        HealthService.HealthResult result = healthService.checkHealth("password");
        assertEquals("WEAK", result.level());
        assertTrue(result.score() <= 40);
    }

    @Test
    void weakPassword_shortNumeric() {
        HealthService.HealthResult result = healthService.checkHealth("123456");
        assertEquals("WEAK", result.level());
    }

    @Test
    void fairPassword_moderateLength() {
        HealthService.HealthResult result = healthService.checkHealth("MyPassword1");
        assertTrue(result.score() > 40);
        assertTrue(result.score() <= 70);
    }

    @Test
    void strongPassword_longAndDiverse() {
        HealthService.HealthResult result = healthService.checkHealth("MyStr0ng!Pass#2024");
        assertTrue(result.score() > 70);
    }

    @Test
    void veryStrongPassword_veryLongAndDiverse() {
        HealthService.HealthResult result = healthService.checkHealth("C0mpl3x!P@ssw0rd#2024$Secure");
        assertEquals("VERY_STRONG", result.level());
        assertTrue(result.score() > 90);
    }

    @Test
    void commonPassword_penalized() {
        HealthService.HealthResult common = healthService.checkHealth("qwerty");
        HealthService.HealthResult uncommon = healthService.checkHealth("xK9#mP2$vL");
        assertTrue(uncommon.score() > common.score());
    }

    @Test
    void scoreBoundedBetween0And100() {
        HealthService.HealthResult result = healthService.checkHealth("a");
        assertTrue(result.score() >= 0);
        assertTrue(result.score() <= 100);
    }

    @Test
    void diversity_allFourClasses() {
        HealthService.HealthResult result = healthService.checkHealth("Abc123!@#LongPassword");
        assertTrue(result.score() >= 70);
    }

    @Test
    void diversity_onlyLowercase() {
        HealthService.HealthResult result = healthService.checkHealth("onlylowercaseletters");
        assertTrue(result.score() < 70);
    }
}
