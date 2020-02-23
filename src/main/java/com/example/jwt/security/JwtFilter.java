package com.example.jwt.security;

import io.jsonwebtoken.JwtException;
import org.jetbrains.annotations.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JwtProvider jwtProvider;

    @Override
    protected void doFilterInternal(@NotNull HttpServletRequest httpServletRequest, @NotNull HttpServletResponse httpServletResponse, @NotNull FilterChain filterChain) throws ServletException, IOException {
        String token = jwtProvider.resolveToken(httpServletRequest);
        try{
            if (token != null && jwtProvider.validateToken(token)){
                Authentication authentication = jwtProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }catch (JwtException exception){
            exception.getMessage();
        }

        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}
