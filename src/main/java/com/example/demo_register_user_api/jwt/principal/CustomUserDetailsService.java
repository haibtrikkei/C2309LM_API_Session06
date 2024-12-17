package com.example.demo_register_user_api.jwt.principal;

import com.example.demo_register_user_api.model.entity.Role;
import com.example.demo_register_user_api.model.entity.Users;
import com.example.demo_register_user_api.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.NoSuchElementException;

@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users users = userRepository.findUsersByUsername(username).orElseThrow(() -> new NoSuchElementException("Khong ton tai user: " + username));
        return CustomUserDetails.builder()
                .username(users.getUsername())
                .password(users.getPassword())
                .address(users.getAdress())
                .fullName(users.getFullName())
                .email(users.getEmail())
                .phone(users.getPhone())
                .enabled(users.getEnabled())
                .authorities(mapToGrandAuthorities(users.getRoles()))
                .build();
    }

    private List<? extends GrantedAuthority> mapToGrandAuthorities(List<Role> roles) {
        return roles.stream().map(role->new SimpleGrantedAuthority(role.getRoleName())).toList();
    }
}
