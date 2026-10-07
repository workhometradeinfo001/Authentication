package org.togo.authentication.controller;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
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
    public ResponseEntity<String> getManualJWt(@RequestParam("email") String email){
        String manualJWT = service.createManualJWT(email);
        return ResponseEntity.ok(manualJWT);
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
