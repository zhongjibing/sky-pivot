package com.icezhg.sky.pivot.dto;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class ApiResponseTest {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    @BeforeEach
    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void successResponse_hasCorrectFields() {
        ApiResponse<String> resp = ApiResponse.success("hello");

        assertEquals("200", resp.code());
        assertEquals("success", resp.message());
        assertEquals("hello", resp.data());
        assertNotNull(resp.requestId());
        assertTrue(resp.requestId().length() >= 32);
        assertTrue(resp.timestamp() > 0);
    }

    @Test
    void requestId_fromMDC_whenSet() {
        String mdcId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        MDC.put("requestId", mdcId);

        ApiResponse<String> resp = ApiResponse.success("hello");

        assertEquals(mdcId, resp.requestId());
    }

    @Test
    void requestId_consistentWithResponseHeader() {
        String mdcId = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        MDC.put("requestId", mdcId);

        ApiResponse<String> resp = ApiResponse.success("hello");

        assertEquals(mdcId, resp.requestId());
        assertEquals(16, resp.requestId().length());
    }

    @Test
    void errorResponse_format_matches_AC6() throws Exception {
        MDC.put("requestId", "aaaaaaaaaaaaaaaa");
        ApiResponse<Void> resp = ApiResponse.error("403", "Forbidden");

        String json = mapper.writeValueAsString(resp);

        assertTrue(json.contains("\"code\":\"403\""));
        assertTrue(json.contains("\"message\":\"Forbidden\""));
        assertTrue(json.contains("\"requestId\":\"aaaaaaaaaaaaaaaa\""));
    }

    @Test
    void errorResponse_withIntCode_convertsToString() {
        ApiResponse<Void> resp = ApiResponse.error(403, "Forbidden");

        assertEquals("403", resp.code());
    }

    @Test
    void success_withoutData_omitsNullInJson() throws Exception {
        MDC.put("requestId", "aaaaaaaaaaaaaaaa");
        ApiResponse<Void> resp = ApiResponse.success();

        String json = mapper.writeValueAsString(resp);

        assertFalse(json.contains("\"data\":"));
    }
}
