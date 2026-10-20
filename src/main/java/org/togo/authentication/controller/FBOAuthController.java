package org.togo.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.togo.authentication.services.FacebookOAuthService;

@Slf4j
@RestController
@RequestMapping("/fb")
@RequiredArgsConstructor
public class FBOAuthController {

    private final FacebookOAuthService fbService;

    @GetMapping("/api/token")
    public String getFacebookToken(
            @RegisteredOAuth2AuthorizedClient("facebook")
            OAuth2AuthorizedClient auth2AuthorizedClient,
            @AuthenticationPrincipal OAuth2User user
    ) throws JsonProcessingException {
        String email = user.getAttribute("email");
        String shortLiveToken = auth2AuthorizedClient.getAccessToken().getTokenValue();
        String longLiveToken = fbService.getLongLivedFacebookToken(shortLiveToken);
        boolean b = fbService.saveIntoMongoLLT(email, longLiveToken);
        if (b){
            boolean result = fbService.saveIntoRedis(email, shortLiveToken);
            if (result) return email;
            else return null;
        }else {
            log.error("Something wrong!!!!");
            return null;
        }
    }


}
