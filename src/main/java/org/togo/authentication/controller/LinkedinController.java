package org.togo.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.togo.authentication.services.LinkedInService;

import java.time.Instant;


@RestController
@RequestMapping("/linkedin")
@RequiredArgsConstructor
public class LinkedinController {

    private final LinkedInService services;

    @GetMapping("/api/token")
    public String linkedinLogin(
            @RegisteredOAuth2AuthorizedClient("linkedin")OAuth2AuthorizedClient authorizedClient,
            @AuthenticationPrincipal OAuth2User user
            ) throws NullPointerException, JsonProcessingException {
        String email = user.getAttribute("email");
        if (email == null){
            email = user.getAttribute("emailAddress");
        }
        String accessToken = authorizedClient.getAccessToken().getTokenValue();
        assert accessToken != null;
        Instant issuedAt = authorizedClient.getAccessToken().getIssuedAt();
        Instant expiresAt = authorizedClient.getAccessToken().getExpiresAt();
        boolean b = services.saveLATIntoRedis(email, accessToken, issuedAt, expiresAt);
        return b ? email : null;
    }


}
