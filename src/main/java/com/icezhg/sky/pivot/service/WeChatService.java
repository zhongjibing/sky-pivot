package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.config.properties.WeChatProperties;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class WeChatService {

    private static final Logger log = LoggerFactory.getLogger(WeChatService.class);

    private static final String MINIAPP_CODE2SESSION_URL =
        "https://api.weixin.qq.com/sns/jscode2session?appid={appid}&secret={secret}&js_code={code}&grant_type=authorization_code";

    private static final String PC_QRCODE_URL =
        "https://open.weixin.qq.com/connect/qrconnect?appid={appid}&redirect_uri={redirectUri}&response_type=code&scope=snsapi_login&state={state}#wechat_redirect";

    private final String miniAppId;
    private final String miniAppSecret;
    private final String pcAppId;
    private final String pcSecret;
    private final RestTemplate restTemplate = new RestTemplate();
    private final JsonMapper objectMapper = JsonMapper.builder().build();

    public WeChatService(WeChatProperties weChatProperties) {
        this.miniAppId = weChatProperties.getAppid();
        this.miniAppSecret = weChatProperties.getSecret();
        this.pcAppId = weChatProperties.getPcAppid();
        this.pcSecret = weChatProperties.getPcSecret();
    }

    public String getMiniAppOpenId(String code) {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("appid", miniAppId);
            params.put("secret", miniAppSecret);
            params.put("code", code);

            String response = restTemplate.getForObject(MINIAPP_CODE2SESSION_URL, String.class, params);
            JsonNode json = objectMapper.readTree(response);

            if (json.has("errcode") && json.get("errcode").asInt() != 0) {
                String errmsg = json.has("errmsg") ? json.get("errmsg").asText() : "Unknown error";
                throw new WeChatException("WeChat login failed: " + errmsg);
            }

            if (!json.has("openid")) {
                throw new WeChatException("WeChat login failed: no openid in response");
            }

            return json.get("openid").asText();
        } catch (WeChatException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get OpenID from WeChat", e);
            throw new WeChatException("Failed to communicate with WeChat API", e);
        }
    }

    public String buildPcQrCodeUrl(String state, String redirectUri) {
        Map<String, String> params = new HashMap<>();
        params.put("appid", pcAppId);
        params.put("redirectUri", redirectUri);
        params.put("state", state);
        return PC_QRCODE_URL.replace("{appid}", pcAppId)
            .replace("{redirectUri}", redirectUri)
            .replace("{state}", state);
    }

    public String getPcOpenId(String code) {
        try {
            String url = String.format(
                "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code",
                pcAppId, pcSecret, code
            );
            String response = restTemplate.getForObject(url, String.class);
            JsonNode json = objectMapper.readTree(response);

            if (json.has("errcode") && json.get("errcode").asInt() != 0) {
                String errmsg = json.has("errmsg") ? json.get("errmsg").asText() : "Unknown error";
                throw new WeChatException("WeChat PC login failed: " + errmsg);
            }

            if (!json.has("openid")) {
                throw new WeChatException("WeChat PC login failed: no openid in response");
            }

            return json.get("openid").asText();
        } catch (WeChatException e) {
            throw e;
        } catch (Exception e) {
            log.error("Failed to get PC OpenID from WeChat", e);
            throw new WeChatException("Failed to communicate with WeChat API", e);
        }
    }

    public static class WeChatException extends RuntimeException {
        public WeChatException(String message) { super(message); }
        public WeChatException(String message, Throwable cause) { super(message, cause); }
    }
}
