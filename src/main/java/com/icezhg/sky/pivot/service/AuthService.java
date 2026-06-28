package com.icezhg.sky.pivot.service;

import com.icezhg.sky.pivot.dto.LoginResponse;
import com.icezhg.sky.pivot.entity.LoginHistory;
import com.icezhg.sky.pivot.entity.User;
import com.icezhg.sky.pivot.repository.LoginHistoryRepository;
import com.icezhg.sky.pivot.repository.UserRepository;
import com.icezhg.sky.pivot.security.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);

    private final UserRepository userRepository;
    private final LoginHistoryRepository loginHistoryRepository;
    private final WeChatService weChatService;
    private final JwtService jwtService;

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

    public static class AccountDeletedException extends RuntimeException {
        public AccountDeletedException() { super("Account has been deleted"); }
    }

    public static class AccountDisabledException extends RuntimeException {
        public AccountDisabledException() { super("Account has been disabled"); }
    }
}
