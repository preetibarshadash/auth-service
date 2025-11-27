package com.preetibarsha.auth_service.security;

import com.preetibarsha.auth_service.entities.RefreshToken;
import com.preetibarsha.auth_service.entities.Users;
import com.preetibarsha.auth_service.repo.RefreshTokenRepo;
import lombok.RequiredArgsConstructor;
import jakarta.servlet.http.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final CustomOAuth2UserService oAuth2UserService;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepo refreshTokenRepository;

    @Value("${app.cookie.domain}")
    private String cookieDomain;

    @Value("${app.cookie.secure:false}")
    private boolean cookieSecure;

    @Value("${app.jwt.refresh-token-expiry-seconds}")
    private long refreshExpirySeconds;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String provider = "google"; // adjust if multiple providers

        // ✅ Get actual Users entity from service
        Users user = oAuth2UserService.processOAuth2User(provider, oauth2User);

        // read remember flag (optional)
        String remember = request.getParameter("remember");

        String accessToken = jwtTokenProvider.createAccessToken(user.getUsername());
        String refreshToken = jwtTokenProvider.createRefreshToken();

        Instant expiry = Instant.now().plusSeconds(
                "true".equalsIgnoreCase(remember) ? refreshExpirySeconds : 24 * 3600
        );

        RefreshToken rt = RefreshToken.builder()
                .token(refreshToken)
                .user(user)
                .expiryDate(expiry)
                .build();
        refreshTokenRepository.save(rt);

        Cookie accessCookie = new Cookie("ACCESS_TOKEN", accessToken);
        accessCookie.setHttpOnly(true);
        accessCookie.setSecure(cookieSecure);
        accessCookie.setPath("/");
        accessCookie.setMaxAge(900); // 15 min
        accessCookie.setDomain(cookieDomain);

        Cookie refreshCookie = new Cookie("REFRESH_TOKEN", refreshToken);
        refreshCookie.setHttpOnly(true);
        refreshCookie.setSecure(cookieSecure);
        refreshCookie.setPath("/");
        refreshCookie.setMaxAge((int) (expiry.getEpochSecond() - Instant.now().getEpochSecond()));
        refreshCookie.setDomain(cookieDomain);

        response.addCookie(accessCookie);
        response.addCookie(refreshCookie);

        // redirect to frontend
        response.sendRedirect("http://localhost:3000");
    }
}
