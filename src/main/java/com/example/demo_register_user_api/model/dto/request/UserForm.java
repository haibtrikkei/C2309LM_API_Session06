package com.example.demo_register_user_api.model.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Set;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class UserForm {
    private String username;
    private String password;
    private String fullName;
    private String address;
    private String email;
    private String phone;
    private Set<String> roles;
}
