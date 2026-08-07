package com.icezhg.sky.pivot.config;

import tools.jackson.databind.json.JsonMapper;
import com.icezhg.sky.pivot.opaque.service.AccessTokenService;
import com.icezhg.sky.pivot.service.SyncEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Component
public class SyncWebSocketHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(SyncWebSocketHandler.class);

    private final Map<Long, List<WebSocketSession>> userSessions = new ConcurrentHashMap<>();
    private final AccessTokenService accessTokenService;
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public SyncWebSocketHandler(AccessTokenService accessTokenService) {
        this.accessTokenService = accessTokenService;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        String token = extractToken(session);
        if (token == null) {
            session.close(CloseStatus.POLICY_VIOLATION);
            return;
        }

        try {
            Long userId = accessTokenService.getUserIdFromAt(token);
            session.getAttributes().put("userId", userId);
            session.getAttributes().put("deviceId", accessTokenService.getDeviceIdFromAt(token));
            userSessions.computeIfAbsent(userId, k -> new CopyOnWriteArrayList<>()).add(session);
            log.info("WebSocket connected for user {}", userId);
        } catch (Exception e) {
            log.warn("WebSocket authentication failed: {}", e.getMessage());
            session.close(CloseStatus.NOT_ACCEPTABLE);
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
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
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        if ("ping".equals(payload)) {
            session.sendMessage(new TextMessage("pong"));
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

    @Async
    @EventListener
    public void onSyncEvent(SyncEvent event) {
        Map<String, Object> notification = Map.of(
                "type", "SYNC",
                "newVersion", event.newVersion(),
                "changedEntries", event.changedEntries()
        );
        notifyChange(event.userId(), notification);
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
}
