package com.momshop.auth.service;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RefreshTokenService {

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";
    private static final Duration REFRESH_TOKEN_EXPIRY = Duration.ofDays(7);

    private final RedisTemplate<String, Object> redisTemplate;

    public RefreshTokenService(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Lưu refresh token vào Redis
     */
    public void saveRefreshToken(String refreshToken, String username) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.opsForValue().set(key, username, REFRESH_TOKEN_EXPIRY);
    }

    /**
     * Lấy username từ refresh token
     */
    public String getUsernameFromRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        Object username = redisTemplate.opsForValue().get(key);
        return username != null ? username.toString() : null;
    }

    /**
     * Xóa refresh token (dùng khi logout)
     */
    public void deleteRefreshToken(String refreshToken) {
        String key = REFRESH_TOKEN_PREFIX + refreshToken;
        redisTemplate.delete(key);
    }

    /**
     * Validate refresh token
     */
    public boolean validateRefreshToken(String refreshToken) {
        String username = getUsernameFromRefreshToken(refreshToken);
        return username != null;
    }
}