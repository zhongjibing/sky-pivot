package com.icezhg.sky.pivot.dto;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ApiResponseTest {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    @Test
    void successResponse_hasCorrectFields() {
        ApiResponse<String> resp = ApiResponse.success("hello");

        assertEquals("200", resp.code());
        assertEquals("success", resp.message());
        assertEquals("hello", resp.data());
        assertNotNull(resp.requestId());
        assertEquals(8, resp.requestId().length());
        assertTrue(resp.timestamp() > 0);
    }

    @Test
    void errorResponse_format_matches_AC6() throws Exception {
        ApiResponse<Void> resp = ApiResponse.error("403", "Forbidden");

        String json = mapper.writeValueAsString(resp);

        assertTrue(json.contains("\"code\":\"403\""));
        assertTrue(json.contains("\"message\":\"Forbidden\""));
        assertTrue(json.contains("\"code\":"));
        assertTrue(json.contains("\"message\":"));
        assertTrue(json.contains("\"requestId\":"));
    }

    @Test
    void errorResponse_withIntCode_convertsToString() {
        ApiResponse<Void> resp = ApiResponse.error(403, "Forbidden");

        assertEquals("403", resp.code());
    }

    @Test
    void success_withoutData_omitsNullInJson() throws Exception {
        ApiResponse<Void> resp = ApiResponse.success();

        String json = mapper.writeValueAsString(resp);

        assertFalse(json.contains("\"data\":"));
    }
}
