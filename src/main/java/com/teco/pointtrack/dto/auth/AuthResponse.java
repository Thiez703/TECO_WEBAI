package com.teco.pointtrack.dto.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;
import lombok.experimental.FieldDefaults;

@Builder
@Data
@AllArgsConstructor
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    String accessToken;
    String refreshToken;

    Long userId;
    String fullName;
    String email;
    String phoneNumber;
    String contact;
    String avatarUrl;
    String role;
}
