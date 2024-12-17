package com.example.demo_register_user_api.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    @GetMapping
    public ResponseEntity<List<String>> getListAdmin(){
        return new ResponseEntity<>(List.of("admin1","admin2","admin3"), HttpStatus.OK);
    }
}
