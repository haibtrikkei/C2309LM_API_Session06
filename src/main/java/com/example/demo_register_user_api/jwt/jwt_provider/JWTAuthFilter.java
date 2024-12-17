package com.example.demo_register_user_api.jwt.jwt_provider;

import com.example.demo_register_user_api.jwt.principal.CustomUserDetails;
import com.example.demo_register_user_api.jwt.principal.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JWTAuthFilter extends OncePerRequestFilter {
    @Autowired
    private JWTProvider jwtProvider;
    @Autowired
    private CustomUserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String jwtToken = getJwtTokenFromRequest(request);
        if(jwtToken!=null && jwtProvider.validateJwtToken(jwtToken)){
            String username = jwtProvider.getUsernameFromJwtToken(jwtToken);
            CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(username);
            Authentication auth = new UsernamePasswordAuthenticationToken(userDetails,null, userDetails.getAuthorities());
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request,response);
    }

    private String getJwtTokenFromRequest(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if(authorization!=null && authorization.startsWith("Bearer "))
            return authorization.substring("Bearer ".length());
        return null;
    }
}
