package org.togo.authentication.entity;


import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document("fb_long_token")
@Getter @Setter
@NoArgsConstructor
@AllArgsConstructor
public class LongLiveTokenEntity {

    @Id
    @Indexed
    private String id;
    private String email;
    private String longLiveToken;
    private String issueDate;
    private String expireDate;
}
