package com.icezhg.sky.pivot.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.icezhg.sky.pivot.dto.LoginResponse;
import com.icezhg.sky.pivot.dto.QrCodeResponse;
import com.icezhg.sky.pivot.dto.QrCodeStatusResponse;
import com.icezhg.sky.pivot.entity.LoginHistory;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.LoginHistoryRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.security.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final WeChatService weChatService;
    private final JwtService jwtService;
    private final Cache<String, QrCodeState> qrCodeCache = Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(10000)
            .build();

    public AuthService(UserRepository userRepository,
                       LoginHistoryRepository loginHistoryRepository,
                       WeChatService weChatService,
                       JwtService jwtService) {
        this.userRepository = userRepository;
        this.loginHistoryRepository = loginHistoryRepository;
        this.weChatService = weChatService;
        this.jwtService = jwtService;
    }

    @Transactional
    public LoginResponse miniAppLogin(String code, String deviceInfo, String ipAddress) {
        String openId = weChatService.getMiniAppOpenId(code);

        User user = userRepository.findByOpenid(openId)
            .orElseGet(() -> createNewUser(openId));

        if (user.getStatus() == 2) {
            throw new AccountDeletedException();
        }
        if (user.getStatus() == 1) {
            throw new AccountDisabledException();
        }

        recordLogin(user.getId(), "MINIAPP", ipAddress, deviceInfo);

        String token = jwtService.issueMiniAppToken(user.getId());

        return new LoginResponse(token, new LoginResponse.UserDto(
            user.getId(),
            user.getNickname(),
            user.getAvatarUrl(),
            user.isMasterPasswordSet()
        ));
    }

    @Transactional
    public LoginResponse pcLogin(String code, String deviceInfo, String ipAddress) {
        String openId = weChatService.getPcOpenId(code);

        User user = userRepository.findByOpenid(openId)
            .orElseGet(() -> createNewUser(openId));

        if (user.getStatus() == 2) {
            throw new AccountDeletedException();
        }
        if (user.getStatus() == 1) {
            throw new AccountDisabledException();
        }

        recordLogin(user.getId(), "PC", ipAddress, deviceInfo);

        String token = jwtService.issuePcToken(user.getId());

        return new LoginResponse(token, new LoginResponse.UserDto(
            user.getId(),
            user.getNickname(),
            user.getAvatarUrl(),
            user.isMasterPasswordSet()
        ));
    }

    public QrCodeResponse generateQrCode() {
        String ticket = UUID.randomUUID().toString();
        String qrCodeUrl = "https://password-manager.example.com/pc/login/scan/" + ticket;

        qrCodeCache.put(ticket, new QrCodeState("WAITING", null, Instant.now().plusSeconds(300)));

        return new QrCodeResponse(ticket, qrCodeUrl);
    }

    public QrCodeStatusResponse checkQrCodeStatus(String ticket) {
        QrCodeState state = qrCodeCache.getIfPresent(ticket);
        if (state == null || state.expiry().isBefore(Instant.now())) {
            return new QrCodeStatusResponse("EXPIRED", null);
        }
        return new QrCodeStatusResponse(state.status(), state.token());
    }

    public void confirmQrCodeLogin(String ticket, String code, String ipAddress) {
        QrCodeState state = qrCodeCache.getIfPresent(ticket);
        if (state == null || state.expiry().isBefore(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "QR code expired");
        }

        LoginResponse loginResponse = pcLogin(code, null, ipAddress);
        qrCodeCache.put(ticket, new QrCodeState("CONFIRMED", loginResponse.token(), state.expiry()));
    }

    private User createNewUser(String openId) {
        User user = new User();
        user.setOpenid(openId);
        user.setStatus(0);
        return userRepository.save(user);
    }

    private void recordLogin(Long userId, String loginType, String ipAddress, String deviceInfo) {
        LoginHistory history = new LoginHistory();
        history.setUserId(userId);
        history.setLoginType(loginType);
        history.setIpAddress(ipAddress);
        history.setDeviceInfo(deviceInfo);
        loginHistoryRepository.save(history);
    }

    private record QrCodeState(String status, String token, Instant expiry) {}

    public static class AccountDeletedException extends RuntimeException {
        public AccountDeletedException() { super("Account has been deleted"); }
    }

    public static class AccountDisabledException extends RuntimeException {
        public AccountDisabledException() { super("Account has been disabled"); }
    }
}
