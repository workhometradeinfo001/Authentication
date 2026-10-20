package org.togo.authentication.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.togo.authentication.services.GoogleOAuthServices;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.Map;

@RestController
@RequestMapping("/oauth")
@RequiredArgsConstructor
@Slf4j
public class GoogleOAuthController {

    private final GoogleOAuthServices services;

    @GetMapping("/token")
    public String getAccessToken(@RegisteredOAuth2AuthorizedClient("google")
                                                        OAuth2AuthorizedClient client,
                                                    @AuthenticationPrincipal OAuth2User user
    ){
        try {
            OAuth2AccessToken accessToken = client.getAccessToken();
            OAuth2RefreshToken refreshToken = client.getRefreshToken();
            String email = user.getAttribute("email");
            assert accessToken.getIssuedAt() != null;
            assert accessToken.getExpiresAt() != null;
            assert refreshToken != null;
            assert refreshToken.getIssuedAt() != null;
            assert refreshToken.getExpiresAt() != null;
            boolean result = services.saveRtOnMongo(
                    email,
                    refreshToken.getTokenValue(),
                    refreshToken.getIssuedAt(),
                    refreshToken.getExpiresAt());
            services.saveAtOnRedis(accessToken.getTokenValue(), email,
                    accessToken.getExpiresAt(), "Google");
            return result ? email : null;
        }catch (Exception e){
            log.error("Something wrong!", e);
            return null;
        }

    }


}
