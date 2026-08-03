package com.icezhg.sky.pivot.security;

import com.icezhg.sky.pivot.common.TokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("JwtAuthInterceptor Tests")
class JwtAuthInterceptorTest {

    private JwtAuthInterceptor interceptor;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        TokenValidator mockValidator = token -> Optional.of(42L);
        interceptor = new JwtAuthInterceptor(List.of(mockValidator));
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("AC-4: ST access to non-auth path should return 403")
    void shouldReturn403ForStOnNonExchangePath() throws Exception {
        String st = StTestHelper.generateValidSt();
        request.addHeader("Authorization", "Bearer " + st);
        request.setRequestURI("/api/vault/items");

        boolean result = interceptor.preHandle(request, response, null);

        assertFalse(result, "Request should be blocked");
        assertEquals(403, response.getStatus(), "ST should get 403 on non-exchange path");
        String content = response.getContentAsString();
        assertTrue(content.contains("Session Token"),
                "Response should mention Session Token restriction");
    }

    @Test
    @DisplayName("AC-4: ST access to /api/vault/items should return 403")
    void shouldReturn403ForStOnVaultPath() throws Exception {
        String st = StTestHelper.generateValidSt();
        request.addHeader("Authorization", "Bearer " + st);
        request.setRequestURI("/api/vault/items");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("AC-4: ST access to /api/vault/search should return 403")
    void shouldReturn403ForStOnSearchPath() throws Exception {
        String st = StTestHelper.generateValidSt();
        request.addHeader("Authorization", "Bearer " + st);
        request.setRequestURI("/api/vault/search");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should return 401 for missing Authorization header")
    void shouldReturn401ForMissingAuthHeader() throws Exception {
        request.setRequestURI("/api/vault/items");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("Should return 401 for non-Bearer Authorization header")
    void shouldReturn401ForNonBearerHeader() throws Exception {
        request.addHeader("Authorization", "Basic dXNlcjpwYXNz");
        request.setRequestURI("/api/vault/items");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("Should set userId attribute for valid non-ST token")
    void shouldSetUserIdForValidNonStToken() throws Exception {
        String nonStToken = StTestHelper.generateNonStToken();
        request.addHeader("Authorization", "Bearer " + nonStToken);
        request.setRequestURI("/api/vault/items");

        assertTrue(interceptor.preHandle(request, response, null));
        assertEquals(42L, request.getAttribute(JwtAuthContext.USER_ID_ATTR));
    }

    @Test
    @DisplayName("Should return 401 for invalid JWT")
    void shouldReturn401ForInvalidJwt() throws Exception {
        JwtAuthInterceptor strictInterceptor = new JwtAuthInterceptor(List.of(token -> Optional.empty()));
        request.addHeader("Authorization", "Bearer not.a.valid.jwt");
        request.setRequestURI("/api/vault/items");

        assertFalse(strictInterceptor.preHandle(request, response, null));
        assertEquals(401, response.getStatus());
    }

    @Test
    @DisplayName("Should reject ST even for device management path")
    void shouldReturn403ForStOnDevicePath() throws Exception {
        String st = StTestHelper.generateValidSt();
        request.addHeader("Authorization", "Bearer " + st);
        request.setRequestURI("/api/devices");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should reject ST even for account deletion path")
    void shouldReturn403ForStOnAccountDeletePath() throws Exception {
        String st = StTestHelper.generateValidSt();
        request.addHeader("Authorization", "Bearer " + st);
        request.setRequestURI("/api/account/delete");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(403, response.getStatus());
    }

    @Test
    @DisplayName("Should reject empty Bearer token")
    void shouldReturn401ForEmptyBearerToken() throws Exception {
        request.addHeader("Authorization", "Bearer ");
        request.setRequestURI("/api/vault/items");

        assertFalse(interceptor.preHandle(request, response, null));
        assertEquals(401, response.getStatus());
    }
}
