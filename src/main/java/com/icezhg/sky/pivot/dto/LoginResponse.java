package com.icezhg.sky.pivot.dto;

public record LoginResponse(String token, UserDto user) {
    public record UserDto(Long id, String nickname, String avatarUrl, boolean masterPasswordSet) {}
}
