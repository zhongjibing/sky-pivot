package com.icezhg.sky.pivot.config;

import tools.jackson.databind.json.JsonMapper;
import com.icezhg.sky.pivot.opaque.service.AccessTokenService;
import com.icezhg.sky.pivot.service.DeviceAuthRequestedEvent;
import com.icezhg.sky.pivot.service.DeviceRevokedEvent;
import com.icezhg.sky.pivot.service.EmergencyAuthUsedEvent;
import com.icezhg.sky.pivot.service.MasterPasswordChangedEvent;
import com.icezhg.sky.pivot.service.RecoveryCodeResetEvent;
import com.icezhg.sky.pivot.service.SyncEvent;
import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

@Component
public class SyncWebSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(SyncWebSocketHandler.class);
    private static final CloseStatus FORCE_LOGOUT_STATUS = new CloseStatus(4001, "FORCE_LOGOUT");
    private static final CloseStatus HEARTBEAT_TIMEOUT_STATUS = new CloseStatus(4002, "HEARTBEAT_TIMEOUT");
    private static final long HEARTBEAT_TIMEOUT_MS = 60_000;
    private static final long HEARTBEAT_CHECK_INTERVAL_MS = 10_000;

    private final Map<Long, List<WebSocketSession>> userSessions = new ConcurrentHashMap<>();
    private final Map<String, SessionMeta> sessionMeta = new ConcurrentHashMap<>();
    private final AccessTokenService accessTokenService;
    private final JsonMapper objectMapper = JsonMapper.builder().build();
    private final ScheduledExecutorService heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "ws-heartbeat");
        t.setDaemon(true);
        return t;
    });

    private ScheduledFuture<?> heartbeatChecker;

    public SyncWebSocketHandler(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
        startHeartbeatChecker();
    }

    private void startHeartbeatChecker() {
        heartbeatChecker = heartbeatExecutor.scheduleWithFixedDelay(
                this::checkHeartbeats, HEARTBEAT_CHECK_INTERVAL_MS,
                HEARTBEAT_CHECK_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        String token = extractToken(session);
        if (token == null) {
            closeSession(session, CloseStatus.POLICY_VIOLATION);
            return;
        }

        try {
            Claims claims = accessTokenService.verifyAccessToken(token);
            Long userId = Long.parseLong(claims.getSubject());
            String deviceId = claims.get("did", String.class);

            long now = Instant.now().toEpochMilli();
            long expiresAtMs;
            if (claims.getExpiration() != null) {
                expiresAtMs = claims.getExpiration().toInstant().toEpochMilli();
            } else {
                expiresAtMs = now + 2 * 60 * 60 * 1000;
            }

            SessionMeta meta = new SessionMeta(userId, deviceId, now, expiresAtMs);
            session.getAttributes().put("userId", userId);
            session.getAttributes().put("deviceId", deviceId);
            session.getAttributes().put("atExpiresAtMs", expiresAtMs);
            sessionMeta.put(session.getId(), meta);
            userSessions.computeIfAbsent(userId, k -> new CopyOnWriteArrayList<>()).add(session);

            log.info("WebSocket connected: userId={}, deviceId={}, sessionId={}, atExpiresAt={}",
                    userId, deviceId, session.getId(), Instant.ofEpochMilli(expiresAtMs));
        } catch (Exception e) {
            log.warn("WebSocket authentication failed: {}", e.getMessage());
            closeSession(session, CloseStatus.NOT_ACCEPTABLE);
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessionMeta.remove(session.getId());
        Long userId = (Long) session.getAttributes().get("userId");
        if (userId != null) {
            List<WebSocketSession> sessions = userSessions.get(userId);
            if (sessions != null) {
                sessions.remove(session);
                if (sessions.isEmpty()) {
                    userSessions.remove(userId);
                }
            }
        }
        log.debug("WebSocket disconnected: sessionId={}, status={}", session.getId(), status);
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) {
        String payload = message.getPayload();
        if ("ping".equals(payload)) {
            handlePing(session);
            return;
        }
        log.debug("Unknown WebSocket message from session={}: {}", session.getId(), payload);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.warn("WebSocket transport error: sessionId={}", session.getId(), exception);
        closeSession(session, CloseStatus.SERVER_ERROR);
    }

    private void handlePing(WebSocketSession session) {
        SessionMeta meta = sessionMeta.get(session.getId());
        if (meta != null) {
            meta.lastPingMs = System.currentTimeMillis();
        }
        try {
            if (session.isOpen()) {
                session.sendMessage(new TextMessage("pong"));
            }
        } catch (IOException e) {
            log.debug("Failed to send pong to session={}", session.getId());
        }

        checkAtExpiry(session);
    }

    private void checkAtExpiry(WebSocketSession session) {
        Long expiresAtMs = (Long) session.getAttributes().get("atExpiresAtMs");
        if (expiresAtMs != null && System.currentTimeMillis() > expiresAtMs) {
            Long userId = (Long) session.getAttributes().get("userId");
            log.info("AT expired for session={}, userId={}, sending FORCE_LOGOUT", session.getId(), userId);
            sendMessage(session, "FORCE_LOGOUT", Map.of("reason", "Access Token expired"));
            closeSession(session, FORCE_LOGOUT_STATUS);
        }
    }

    private void checkHeartbeats() {
        long now = System.currentTimeMillis();
        for (Map.Entry<String, SessionMeta> entry : sessionMeta.entrySet()) {
            SessionMeta meta = entry.getValue();
            if (now - meta.lastPingMs > HEARTBEAT_TIMEOUT_MS) {
                String sessionId = entry.getKey();
                log.info("Heartbeat timeout for session={}, userId={}", sessionId, meta.userId);
                WebSocketSession session = findSessionById(sessionId);
                if (session != null) {
                    sendMessage(session, "FORCE_LOGOUT", Map.of("reason", "Heartbeat timeout"));
                    closeSession(session, HEARTBEAT_TIMEOUT_STATUS);
                }
                sessionMeta.remove(sessionId);
            }
        }
    }

    @Async
    @EventListener
    public void onSyncEvent(SyncEvent event) {
        Map<String, Object> payload = new java.util.LinkedHashMap<>();
        payload.put("newVersion", event.newVersion());
        if (event.changedEntries() != null) {
            payload.put("changedItemIds", event.changedEntries().stream()
                    .map(e -> e.targetId() != null ? e.targetId() : "")
                    .filter(s -> !s.isEmpty())
                    .toList());
        }
        broadcastToUser(event.userId(), "SYNC", payload, null);
    }

    @Async
    @EventListener
    public void onDeviceRevoked(DeviceRevokedEvent event) {
        Map<String, Object> payload = Map.of(
                "deviceId", event.deviceId(),
                "deviceName", event.deviceName() != null ? event.deviceName() : ""
        );
        broadcastToAllUserDevices(event.userId(), "DEVICE_REVOKED", payload);
    }

    @Async
    @EventListener
    public void onDeviceAuthRequested(DeviceAuthRequestedEvent event) {
        Map<String, Object> payload = Map.of(
                "requestId", event.requestId(),
                "deviceName", event.deviceName() != null ? event.deviceName() : "",
                "fingerprint", event.fingerprint() != null ? event.fingerprint() : ""
        );
        broadcastToUser(event.userId(), "DEVICE_AUTH_REQ", payload, null);
    }

    @Async
    @EventListener
    public void onMasterPasswordChanged(MasterPasswordChangedEvent event) {
        Map<String, Object> payload = Map.of("message", "Master password has been changed");
        broadcastToUserExceptAll(event.userId(), "MASTER_PASSWORD_CHANGED", payload);
    }

    @Async
    @EventListener
    public void onRecoveryCodeReset(RecoveryCodeResetEvent event) {
        Map<String, Object> payload = Map.of("message", "Recovery code has been reset");
        broadcastToUser(event.userId(), "RECOVERY_CODE_RESET", payload, null);
    }

    @Async
    @EventListener
    public void onEmergencyAuthUsed(EmergencyAuthUsedEvent event) {
        Map<String, Object> payload = Map.of(
                "deviceId", event.deviceId(),
                "deviceName", event.deviceName() != null ? event.deviceName() : ""
        );
        broadcastToUser(event.userId(), "EMERGENCY_AUTH_USED", payload, event.deviceId());
    }

    private void broadcastToAllUserDevices(Long userId, String type, Map<String, Object> payload) {
        List<WebSocketSession> sessions = userSessions.get(userId);
        if (sessions == null || sessions.isEmpty()) return;

        Map<String, Object> message = Map.of(
                "type", type,
                "timestamp", System.currentTimeMillis(),
                "payload", payload
        );

        String json;
        try {
            json = objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            log.error("Failed to serialize {} message for userId={}", type, userId, e);
            return;
        }

        TextMessage textMessage = new TextMessage(json);
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) continue;
            try {
                session.sendMessage(textMessage);
            } catch (IOException e) {
                log.debug("Failed to send {} to session={}", type, session.getId());
            }
        }
    }

    private void broadcastToUser(Long userId, String type, Map<String, Object> payload, String excludeDeviceId) {
        List<WebSocketSession> sessions = userSessions.get(userId);
        if (sessions == null || sessions.isEmpty()) return;

        Map<String, Object> message = Map.of(
                "type", type,
                "timestamp", System.currentTimeMillis(),
                "payload", payload
        );

        String json;
        try {
            json = objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            log.error("Failed to serialize {} message for userId={}", type, userId, e);
            return;
        }

        TextMessage textMessage = new TextMessage(json);
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) continue;
            if (excludeDeviceId != null) {
                String sessionDeviceId = (String) session.getAttributes().get("deviceId");
                if (excludeDeviceId.equals(sessionDeviceId)) continue;
            }
            try {
                session.sendMessage(textMessage);
            } catch (IOException e) {
                log.debug("Failed to send {} to session={}", type, session.getId());
            }
        }
    }

    private void broadcastToUserExceptAll(Long userId, String type, Map<String, Object> payload) {
        List<WebSocketSession> sessions = userSessions.get(userId);
        if (sessions == null || sessions.isEmpty()) return;

        Map<String, Object> message = Map.of(
                "type", type,
                "timestamp", System.currentTimeMillis(),
                "payload", payload
        );

        String json;
        try {
            json = objectMapper.writeValueAsString(message);
        } catch (Exception e) {
            log.error("Failed to serialize {} message for userId={}", type, userId, e);
            return;
        }

        TextMessage textMessage = new TextMessage(json);
        for (WebSocketSession session : sessions) {
            if (!session.isOpen()) continue;
            try {
                session.sendMessage(textMessage);
            } catch (IOException e) {
                log.debug("Failed to send {} to session={}", type, session.getId());
            }
        }
    }

    private void sendMessage(WebSocketSession session, String type, Map<String, Object> payload) {
        if (!session.isOpen()) return;
        try {
            Map<String, Object> message = Map.of(
                    "type", type,
                    "timestamp", System.currentTimeMillis(),
                    "payload", payload
            );
            String json = objectMapper.writeValueAsString(message);
            session.sendMessage(new TextMessage(json));
        } catch (IOException e) {
            log.debug("Failed to send {} to session={}", type, session.getId());
        }
    }

    public void notifyChange(Long userId, Object changeData) {
        List<WebSocketSession> sessions = userSessions.get(userId);
        if (sessions == null || sessions.isEmpty()) return;

        try {
            String json = objectMapper.writeValueAsString(changeData);
            TextMessage message = new TextMessage(json);
            for (WebSocketSession session : sessions) {
                if (session.isOpen()) {
                    try {
                        session.sendMessage(message);
                    } catch (IOException e) {
                        log.warn("Failed to send WebSocket message to user {}", userId, e);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Failed to serialize change data", e);
        }
    }

    private WebSocketSession findSessionById(String sessionId) {
        for (List<WebSocketSession> sessions : userSessions.values()) {
            for (WebSocketSession s : sessions) {
                if (s.getId().equals(sessionId)) return s;
            }
        }
        return null;
    }

    private void closeSession(WebSocketSession session, CloseStatus status) {
        try {
            if (session.isOpen()) {
                session.close(status);
            }
        } catch (IOException e) {
            log.debug("Error closing session={}", session.getId(), e);
        }
    }

    private String extractToken(WebSocketSession session) {
        String query = session.getUri() != null ? session.getUri().getQuery() : null;
        if (query != null) {
            for (String param : query.split("&")) {
                if (param.startsWith("token=")) {
                    return param.substring(6);
                }
            }
        }
        return null;
    }

    private static class SessionMeta {
        final Long userId;
        final String deviceId;
        volatile long lastPingMs;
        final long atExpiresAtMs;

        SessionMeta(Long userId, String deviceId, long lastPingMs, long atExpiresAtMs) {
            this.userId = userId;
            this.deviceId = deviceId;
            this.lastPingMs = lastPingMs;
            this.atExpiresAtMs = atExpiresAtMs;
        }
    }
}
