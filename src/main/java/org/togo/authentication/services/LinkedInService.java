package org.togo.authentication.services;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.io.Serializable;
import java.time.Instant;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class LinkedInService {

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public boolean saveLATIntoRedis(String email, String accessToken, Instant iDate, Instant eDate) throws JsonProcessingException {
        Map<String, ? extends Serializable> obj = Map.of(
                "Access_Token", accessToken,
                "Issue_Date", iDate,
                "Expire_Date", eDate,
                "Login_With", "LinkedIn"
        );
        String objToString = objectMapper.writeValueAsString(obj);
        redisTemplate.opsForValue().set(email, objToString);
        return true;
    }


}
