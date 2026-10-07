package org.togo.authentication.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;
import org.togo.authentication.entity.LongLiveTokenEntity;
import org.togo.authentication.repo.mongodb.FbMongoRepo;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class FacebookOAuthService {

    private final MongoTemplate mongoTemplate;
    private final FbMongoRepo mongoRepo;
    private final StringRedisTemplate redisTemplate;
    @Value("${app.fb.id}")
    private String fbAppId;
    @Value("${app.fb.secret}")
    private String fbAppSecret;
    private final Instant now = Instant.now();
    long expiresInSeconds = 5183944L;

    public String getLongLivedFacebookToken(String shortLivedToken) {
        String url = UriComponentsBuilder.fromHttpUrl("https://graph.facebook.com/v19.0/oauth/access_token")
                .queryParam("grant_type", "fb_exchange_token")
                .queryParam("client_id", fbAppId)
                .queryParam("client_secret", fbAppSecret)
                .queryParam("fb_exchange_token", shortLivedToken)
                .toUriString();
        RestTemplate restTemplate = new RestTemplate();
        Map response = restTemplate.getForObject(url, Map.class);

        // Returns a 60-day access token
        assert response != null;
        return (String) response.get("access_token");
    }

    public boolean saveIntoMongoLLT(String email, String longLiveToken){
        try {
            Query q = new Query();
            q.addCriteria(Criteria.where("email").is(email));
            List<LongLiveTokenEntity> list = mongoTemplate.find(q, LongLiveTokenEntity.class);
            if (list.isEmpty()){
                LongLiveTokenEntity llTE = new LongLiveTokenEntity();
                llTE.setEmail(email);
                llTE.setLongLiveToken(longLiveToken);
                llTE.setIssueDate(now.toString());
                llTE.setExpireDate(now.plusSeconds(expiresInSeconds).toString());
                mongoRepo.save(llTE);
            }else{
                LongLiveTokenEntity existsData = list.getFirst();
                existsData.setLongLiveToken(longLiveToken);
                existsData.setIssueDate(now.toString());
                existsData.setExpireDate(now.plusSeconds(expiresInSeconds).toString());
                mongoRepo.save(existsData);
            }
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public boolean saveIntoRedis(String email, String accessToken) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, String> obj = Map.of(
                "Short_Live_Token", accessToken,
                "Email", email,
                "Login_With", "Facebook"
        );
        String objString = objectMapper.writeValueAsString(obj);
        redisTemplate.opsForValue().set(email, objString);
        return true;
    }

}
