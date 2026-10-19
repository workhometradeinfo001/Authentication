package org.togo.authentication.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.togo.authentication.DTO.ManualJwtVerifyDTO;
import org.togo.authentication.services.ManualJWTService;

import java.time.Instant;
import java.util.Objects;

@RestController
@RequestMapping("/jwt")
@RequiredArgsConstructor
public class ManualJWTController {

    private final ManualJWTService service;

    @GetMapping("/token")
    public ResponseEntity<HttpStatus> getManualJWt(@RequestParam("email") String email)
            throws JsonProcessingException {
        String manualJWT = service.createManualJWT(email);
        boolean b = service.saveManualJWTIntoRedis(manualJWT, email);
        if (b){
            return ResponseEntity.ok(HttpStatus.CREATED);
        }else {
            return ResponseEntity.ok(HttpStatus.NOT_FOUND);
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<?> getVerifyToken(@RequestBody ManualJwtVerifyDTO dto){
        Claims decodeTheToken = service.getDecodeTheToken(dto.getToken());
        if (Objects.equals(decodeTheToken.getExpiration(), Instant.now())){
            return ResponseEntity.badRequest().build();
        }else {
            return ResponseEntity.ok(decodeTheToken);
        }
    }

}
