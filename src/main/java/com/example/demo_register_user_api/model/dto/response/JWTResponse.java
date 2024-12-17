package com.example.demo_register_user_api.model.dto.response;

import lombok.*;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Builder
public class JWTResponse {
    private String username;
    private String fullName;
    private String address;
    private String email;
    private Boolean enabled;
    private Collection<? extends GrantedAuthority> authorities;
    private String jwtToken;
}
