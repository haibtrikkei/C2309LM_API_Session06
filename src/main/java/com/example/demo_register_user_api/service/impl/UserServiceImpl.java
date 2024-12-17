package com.example.demo_register_user_api.service.impl;

import com.example.demo_register_user_api.jwt.jwt_provider.JWTProvider;
import com.example.demo_register_user_api.jwt.principal.CustomUserDetails;
import com.example.demo_register_user_api.model.dto.request.UserForm;
import com.example.demo_register_user_api.model.dto.request.UserLogin;
import com.example.demo_register_user_api.model.dto.response.JWTResponse;
import com.example.demo_register_user_api.model.entity.Role;
import com.example.demo_register_user_api.model.entity.Users;
import com.example.demo_register_user_api.repository.RoleRepository;
import com.example.demo_register_user_api.repository.UserRepository;
import com.example.demo_register_user_api.service.UserService;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Set;

@Service
public class UserServiceImpl implements UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JWTProvider jwtProvider;

    @Override
    public Users insertUser(UserForm userForm) {
        Users users = Users.builder()
                .username(userForm.getUsername())
                .password(BCrypt.hashpw(userForm.getPassword(),BCrypt.gensalt(12)))
                .fullName(userForm.getFullName())
                .adress(userForm.getAddress())
                .email(userForm.getEmail())
                .phone(userForm.getPhone())
                .roles(mapToRoles(userForm.getRoles()))
                .enabled(true)
                .build();
        return userRepository.save(users);
    }

    @Override
    public JWTResponse login(UserLogin userLogin) {
        Authentication authentication = null;
        try {
            authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLogin.getUsername(),userLogin.getPassword()));
        }catch (Exception ex){
            System.out.println("Sai username hoac password!");
        }
        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
        return JWTResponse.builder()
                .username(userLogin.getUsername())
                .fullName(userDetails.getFullName())
                .address(userDetails.getAddress())
                .email(userDetails.getEmail())
                .enabled(userDetails.getEnabled())
                .authorities(userDetails.getAuthorities())
                .jwtToken(jwtProvider.generateJwtToken(userDetails))
                .build();
    }

    private List<Role> mapToRoles(Set<String> roles) {
        List<Role> listRoles = new ArrayList<>();
        if(!roles.isEmpty()){
            roles.stream().forEach(role -> {
                switch (role){
                    case "ROLE_ADMIN":
                        listRoles.add(roleRepository.findRoleByRoleName(role).orElseThrow(()->new NoSuchElementException("Khong ton tai role admin!")));
                        break;
                    case "ROLE_USER":
                        listRoles.add(roleRepository.findRoleByRoleName(role).orElseThrow(()->new NoSuchElementException("Khong ton tai role user!")));
                        break;
                    case "ROLE_MODERATOR":
                        listRoles.add(roleRepository.findRoleByRoleName(role).orElseThrow(()->new NoSuchElementException("Khong ton tai role moderatory!")));
                        break;
                }
            });
        }else{
            listRoles.add(roleRepository.findRoleByRoleName("ROLE_USER").orElseThrow(()->new NoSuchElementException("Khong ton tai role user!")));
        }

        return listRoles;
    }
}
