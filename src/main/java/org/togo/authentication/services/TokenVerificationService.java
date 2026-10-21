package org.togo.authentication.services;


import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.togo.authentication.records.fb.FbDebugResponse;

import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TokenVerificationService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
    @Value("${spring.security.oauth2.client.registration.facebook.client-id}")
    private String appFbId;
    @Value("${spring.security.oauth2.client.registration.facebook.client-secret}")
    private String appFbSecret;
    private final RestClient restClient = RestClient.create();


    public boolean tokenVerify(String email){

        try {
            String stringResult = redisTemplate.opsForValue().get(email);
            assert stringResult != null;
            if (!stringResult.isEmpty()){
                Map<String, String> stringStringMap = objectMapper.readValue(
                        stringResult, new TypeReference<>() {
                        });
                String loginWith = stringStringMap.get("Login_With");
                return switch (loginWith) {
                    case "Facebook" -> {
                        String fbToken = stringStringMap.get("Short_Live_Token");
                        yield loginWithFB(fbToken);
                    }
                    case "Google" -> {
                        Instant expireDateG = Instant.parse(stringStringMap.get("Expire_Date"));
                        yield verifyExpirationOfDate(expireDateG);
                    }
                    case "LinkedIn" -> {
                        Instant expireDateL = Instant.parse(stringStringMap.get("Expire_Date"));
                        yield verifyExpirationOfDate(expireDateL);
                    }
                    case "Manual" -> {
                        Instant expireDateM = Instant.parse(stringStringMap.get("Expire_Date"));
                        yield verifyExpirationOfDate(expireDateM);
                    }
                    default -> false;
                };
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return false;
    }

    public boolean loginWithFB(String token){
        String appAccessToken = appFbId + "|" + appFbSecret;
        String urlForValidation = "https://graph.facebook.com/debug_token?input_token={token}&access_token={appAccessToken}";
        try {
            FbDebugResponse response = restClient.get()
                    .uri(urlForValidation, token, appAccessToken)
                    .retrieve()
                    .body(FbDebugResponse.class);
            if (response == null || response.data() == null){return false;}
            FbDebugResponse.FbDebugData data = response.data();
            return data.isValid() && appFbId.equals(data.appId());

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verifyExpirationOfDate(Instant expireDate){
        if (expireDate == null) {return false;}
        //Return true if valid, false for expire date.
        return Instant.now().isBefore(expireDate);
    }

}
