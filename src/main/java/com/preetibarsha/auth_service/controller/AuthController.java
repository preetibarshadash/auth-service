package com.preetibarsha.auth_service.controller;

import com.preetibarsha.auth_service.dto.*;
import com.preetibarsha.auth_service.entities.*;
import com.preetibarsha.auth_service.repo.*;
import com.preetibarsha.auth_service.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.*;
import java.time.Instant;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class AuthController {

    private final UserRepo usersRepository;
    private final RefreshTokenRepo refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.jwt.refresh-token-expiry-seconds}")
    private long refreshExpirySeconds;

    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Users user) {
        if (usersRepository.existsByUsername(user.getUsername()))
            return ResponseEntity.badRequest().body("username exists");
        if (usersRepository.existsByEmail(user.getEmail()))
            return ResponseEntity.badRequest().body("email exists");

        user.setPassword(passwordEncoder.encode(user.getPassword()));
        usersRepository.save(user);
        return ResponseEntity.ok("registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest req, HttpServletResponse response) {

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.getUsername(), req.getPassword())
        );

        if (!auth.isAuthenticated()) {
            return ResponseEntity.status(401).body("invalid credentials");
        }

        // issue tokens
        String accessToken = jwtTokenProvider.createAccessToken(req.getUsername());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        Users user = usersRepository.findByUsername(req.getUsername()).orElseThrow();

        Instant expiry = Instant.now().plusSeconds(Boolean.TRUE.equals(req.getRemember()) ? refreshExpirySeconds : 24 * 3600);

        RefreshToken rt = RefreshToken.builder()
                .token(refreshToken)
                .user(user)
                .expiryDate(expiry)
                .build();
        refreshTokenRepository.save(rt);

        // set cookies
        Cookie ac = new Cookie("ACCESS_TOKEN", accessToken);
        ac.setHttpOnly(true);
        ac.setSecure(cookieSecure);
        ac.setPath("/");
        ac.setMaxAge(900);
        ac.setDomain(cookieDomain);

        Cookie rc = new Cookie("REFRESH_TOKEN", refreshToken);
        rc.setHttpOnly(true);
        rc.setSecure(cookieSecure);
        rc.setPath("/");
        rc.setMaxAge((int) (expiry.getEpochSecond() - Instant.now().getEpochSecond()));
        rc.setDomain(cookieDomain);

        response.addCookie(ac);
        response.addCookie(rc);

        return ResponseEntity.ok(new AuthResponse(accessToken, refreshToken));
    }

    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("REFRESH_TOKEN".equals(c.getName())) {
                    refreshToken = c.getValue(); break;
                }
            }
        }
        if (refreshToken == null) return ResponseEntity.status(401).body("no refresh token");

        RefreshToken rt = refreshTokenRepository.findByToken(refreshToken).orElse(null);
        if (rt == null || rt.getExpiryDate().isBefore(Instant.now())) {
            return ResponseEntity.status(401).body("invalid/expired refresh token");
        }

        // rotate
        String newAccess = jwtTokenProvider.createAccessToken(rt.getUser().getUsername());
        String newRefresh = jwtTokenProvider.createRefreshToken();
        rt.setToken(newRefresh);
        rt.setExpiryDate(Instant.now().plusSeconds(refreshExpirySeconds));
        refreshTokenRepository.save(rt);

        Cookie ac = new Cookie("ACCESS_TOKEN", newAccess);
        ac.setHttpOnly(true);
        ac.setPath("/");
        ac.setMaxAge(900);
        ac.setDomain(cookieDomain);
        ac.setSecure(cookieSecure);

        Cookie rc = new Cookie("REFRESH_TOKEN", newRefresh);
        rc.setHttpOnly(true);
        rc.setPath("/");
        rc.setMaxAge((int) refreshExpirySeconds);
        rc.setDomain(cookieDomain);
        rc.setSecure(cookieSecure);

        response.addCookie(ac);
        response.addCookie(rc);

        return ResponseEntity.ok(new AuthResponse(newAccess, newRefresh));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = null;
        if (request.getCookies() != null) {
            for (Cookie c : request.getCookies()) {
                if ("REFRESH_TOKEN".equals(c.getName())) {
                    refreshToken = c.getValue(); break;
                }
            }
        }
        if (refreshToken != null) {
            refreshTokenRepository.findByToken(refreshToken).ifPresent(refreshTokenRepository::delete);
        }

        Cookie ac = new Cookie("ACCESS_TOKEN", null);
        ac.setPath("/");
        ac.setMaxAge(0);
        ac.setDomain(cookieDomain);

        Cookie rc = new Cookie("REFRESH_TOKEN", null);
        rc.setPath("/");
        rc.setMaxAge(0);
        rc.setDomain(cookieDomain);

        response.addCookie(ac);
        response.addCookie(rc);

        return ResponseEntity.ok("logged out");
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(@CookieValue(name = "ACCESS_TOKEN", required = false) String token) {
        if (token == null) return ResponseEntity.status(401).body("Not logged in");

        String username = jwtTokenProvider.getUsernameFromAccessToken(token);
        Users user = usersRepository.findByUsername(username).orElse(null);
        if (user == null) return ResponseEntity.status(401).body("Not logged in");

        return ResponseEntity.ok(user);
    }

}
