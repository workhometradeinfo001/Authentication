package org.togo.authentication.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

@Document("refresh_token")
@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenEntity {

    @Id
    @Indexed
    private String id;
    private String email;
    private String refreshToken;
    private Instant issueAt;
    private Instant expireAt;

}
