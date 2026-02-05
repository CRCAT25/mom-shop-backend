package com.momshop.auth.controller;

import com.momshop.auth.dto.AuthRequest;
import com.momshop.auth.dto.LoginRequest;
import com.momshop.auth.dto.LoginResponse;
import com.momshop.auth.dto.RefreshTokenRequest;
import com.momshop.auth.service.AuthService;
import com.momshop.auth.service.RefreshTokenService;
import com.momshop.auth.util.JwtUtil;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtUtil jwtUtil,
            AuthService authService,
            RefreshTokenService refreshTokenService
    ) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.authService = authService;
        this.refreshTokenService = refreshTokenService;
    }

    /**
     * Register endpoint
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody AuthRequest request) {
        authService.register(request);
        return ResponseEntity.ok("User registered successfully");
    }

    /**
     * Login endpoint
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest request) {

        // Authenticate user
        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        UserDetails user = (UserDetails) auth.getPrincipal();

        // Generate tokens
        String accessToken = jwtUtil.generateToken(user.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken();

        // Lưu refresh token vào Redis (chỉ lưu username, KHÔNG lưu UserDetails object)
        refreshTokenService.saveRefreshToken(refreshToken, user.getUsername());

        return ResponseEntity.ok(new LoginResponse(accessToken, refreshToken));
    }

    /**
     * Refresh token endpoint - tạo access token mới từ refresh token
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {

        String refreshToken = request.getRefreshToken();

        // Validate refresh token
        if (!refreshTokenService.validateRefreshToken(refreshToken)) {
            return ResponseEntity.status(401).body("Invalid or expired refresh token");
        }

        // Lấy username từ refresh token
        String username = refreshTokenService.getUsernameFromRefreshToken(refreshToken);

        if (username == null) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }

        // Generate new access token
        String newAccessToken = jwtUtil.generateToken(username);

        return ResponseEntity.ok(new LoginResponse(newAccessToken, refreshToken));
    }

    /**
     * Logout endpoint - xóa refresh token
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody RefreshTokenRequest request) {
        refreshTokenService.deleteRefreshToken(request.getRefreshToken());
        return ResponseEntity.ok("Logged out successfully");
    }
}