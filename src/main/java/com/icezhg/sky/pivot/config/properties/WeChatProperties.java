package com.icezhg.sky.pivot.config.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("app.wechat")
public class WeChatProperties {

    private String appid = "";
    private String secret = "";
    private String pcAppid = "";
    private String pcSecret = "";
}
