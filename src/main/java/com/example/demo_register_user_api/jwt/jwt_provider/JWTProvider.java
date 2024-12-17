package com.example.demo_register_user_api.jwt.jwt_provider;

import com.example.demo_register_user_api.jwt.principal.CustomUserDetails;
import io.jsonwebtoken.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JWTProvider {
    @Value("${secret}")
    private String secret;
    @Value("${expire}")
    private Long expire;

    public String generateJwtToken(CustomUserDetails userDetails){
        Date today = new Date();
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(today)
                .setExpiration(new Date(today.getTime()+expire))
                .signWith(SignatureAlgorithm.HS512,secret)
                .compact();
    }

    public boolean validateJwtToken(String jwtToken){
        try {
            Jwts.parser().setSigningKey(secret).parseClaimsJws(jwtToken);
            return true;
        }catch (UnsupportedJwtException ex){
            System.out.println("Server api khong ho tro jwt");
        }catch (MalformedJwtException ex){
            System.out.println("Chuoi jwt khong dung dinh dang");
        }catch (ExpiredJwtException ex){
            System.out.println("Chuoi jwt het han");
        }catch (JwtException ex){
            System.out.println("Co loi: "+ex.getMessage());
        }
        return  false;
    }

    public String getUsernameFromJwtToken(String jwtToken){
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(jwtToken).getBody().getSubject();
    }
}
