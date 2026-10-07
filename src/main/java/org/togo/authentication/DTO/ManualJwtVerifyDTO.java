package org.togo.authentication.DTO;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

@Getter @Setter
public class ManualJwtVerifyDTO {
    @NonNull
    private String token;
}
