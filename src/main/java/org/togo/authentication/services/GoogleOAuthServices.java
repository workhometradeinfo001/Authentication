package org.togo.authentication.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;
import org.togo.authentication.entity.RefreshTokenEntity;
import org.togo.authentication.repo.mongodb.GoogleMongoRepo;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class GoogleOAuthServices {

    private final GoogleMongoRepo mongoRepo;
    private final MongoTemplate mongoTemplate;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public boolean saveRtOnMongo(String email, String rT, Instant iDate, Instant eDate){
        try {
            Instant thirtyDays = Instant.now().plus(Duration.ofDays(30));
            Instant isExpirationNull = (eDate == null) ? thirtyDays : eDate;
            Query q = new Query();
            q.addCriteria(Criteria.where("email").is(email));
            List<RefreshTokenEntity> searchingObj = mongoTemplate.find(q, RefreshTokenEntity.class);
            if (!searchingObj.isEmpty()){
                RefreshTokenEntity object = searchingObj.getFirst();
                object.setRefreshToken(rT);
                object.setIssueAt(iDate);
                object.setExpireAt(isExpirationNull);
                mongoRepo.save(object);
            }else {
                RefreshTokenEntity rt = new RefreshTokenEntity();
                rt.setRefreshToken(rT);
                rt.setIssueAt(iDate);
                rt.setExpireAt(isExpirationNull);
                rt.setEmail(email);
                mongoRepo.save(rt);
            }
            return true;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }
    public void saveAtOnRedis(String accessToken, String email,
                              Instant eDate, String loginMethod){
        Map<String, ? extends Serializable> obj = Map.of(
                "Access_Token", accessToken,
                "Expire_Date", eDate,
                "Login_With", loginMethod
        );
        try {
            String s = objectMapper.writeValueAsString(obj);
            redisTemplate.opsForValue().set(email, s, Duration.ofDays(7));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

}
