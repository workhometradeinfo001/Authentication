package org.togo.authentication.records.fb;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public record FbDebugResponse(FbDebugData data ) {

    public record FbDebugData(
            @JsonProperty("app_id") String appId,
            @JsonProperty("is_valid") boolean isValid,
            @JsonProperty("user_id") String userId,
            @JsonProperty("expires_at") long expiresAt,
            List<String> scopes
    ) {}

}
