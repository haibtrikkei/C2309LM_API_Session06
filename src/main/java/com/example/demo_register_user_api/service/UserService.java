package com.example.demo_register_user_api.service;

import com.example.demo_register_user_api.model.dto.request.UserForm;
import com.example.demo_register_user_api.model.dto.request.UserLogin;
import com.example.demo_register_user_api.model.dto.response.JWTResponse;
import com.example.demo_register_user_api.model.entity.Users;

import java.util.Optional;

public interface UserService {
    Users insertUser(UserForm userForm);
    JWTResponse login(UserLogin userLogin);
}
