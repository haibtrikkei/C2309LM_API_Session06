package com.example.demo_register_user_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class UserController {
    @GetMapping
    public ResponseEntity<List<String>> getListUsers(){
        return new ResponseEntity<>(List.of("user1","user2","user3"), HttpStatus.OK);
    }
}