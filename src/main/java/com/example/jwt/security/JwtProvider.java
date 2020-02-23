package com.example.jwt.security;

import com.example.jwt.service.MyUserDetailsService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Collectors;

@Component
public class JwtProvider {

    @Value("${pius.jwtSecret}")
    private String secretKey;

    @Value("${pius.jwtExpirationMs}")
    private Long validity;

    private MyUserDetailsService myUserDetailsService;

    @Autowired
    public JwtProvider(MyUserDetailsService myUserDetailsService){
        this.myUserDetailsService = myUserDetailsService;
    }

    @PostConstruct
    protected void init(){
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username, List<GrantedAuthority> roles){
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("auth", roles.stream().map(s -> new SimpleGrantedAuthority(s.getAuthority())).filter(Objects::nonNull).collect(Collectors.toList()));
        Date now = new Date();
        Date valid = new Date(now.getTime() + validity);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(valid)
                .signWith(SignatureAlgorithm.HS256, secretKey)

                .compact();
    }

    public Authentication getAuthentication(String token){
        UserDetails userDetails = myUserDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities() );

    }

    public String getUsername(String token){
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest request){
        String bearer = request.getHeader("Authorization");
        if (bearer !=  null && bearer.startsWith("Bearer ")){
            return bearer.substring(7);
        }
        return null;
    }

    public boolean validateToken(String token){
        boolean ret = false;
        try{
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            ret = true;
        }catch (JwtException | IllegalArgumentException exception){
            exception.getMessage();
        }
        return ret;
    }

    public String generateToken(UserDetails userDetails){
        List<GrantedAuthority> roles = new  ArrayList<>();
        return createToken(userDetails.getUsername(), roles);
    }
}
