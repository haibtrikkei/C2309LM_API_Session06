package com.example.demo_register_user_api.controller;

import com.example.demo_register_user_api.model.dto.request.UserForm;
import com.example.demo_register_user_api.model.dto.request.UserLogin;
import com.example.demo_register_user_api.model.dto.response.DataResponse;
import com.example.demo_register_user_api.model.dto.response.JWTResponse;
import com.example.demo_register_user_api.model.entity.Users;
import com.example.demo_register_user_api.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
    @Autowired
    private UserService userService;

    @PostMapping("/register")
    public ResponseEntity<DataResponse<Users>> registerUser(@RequestBody UserForm userForm){
        return new ResponseEntity<>(new DataResponse<>(userService.insertUser(userForm), HttpStatus.CREATED),HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<DataResponse<JWTResponse>> login(@RequestBody UserLogin userLogin){
        return  new ResponseEntity<>(new DataResponse<>(userService.login(userLogin),HttpStatus.OK),HttpStatus.OK);
    }
}
