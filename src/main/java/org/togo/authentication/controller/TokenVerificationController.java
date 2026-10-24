package org.togo.authentication.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.togo.authentication.DTO.TokenVerificationDTO;
import org.togo.authentication.services.TokenVerificationService;

@RestController
@RequestMapping("/gToken")
@RequiredArgsConstructor
public class TokenVerificationController {

    private final TokenVerificationService service;

    @PostMapping("/verification")
    public ResponseEntity<HttpStatus> isValidToken(@RequestBody TokenVerificationDTO dto){
        boolean result = service.tokenVerify(dto.getEmail());
        return result ? new ResponseEntity<>(HttpStatus.ACCEPTED) :
                new ResponseEntity<>(HttpStatus.NOT_ACCEPTABLE);
    }


}
