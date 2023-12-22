package com.reznik.jwtsecurity.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    @JsonProperty("acess_token")
    private String accessToken;

    @JsonProperty("refresh_token")
    private String refreshToken;

}
