package com.example.jwt.controller;

import com.example.jwt.model.EnumRole;
import com.example.jwt.model.Role;
import com.example.jwt.model.User;
import com.example.jwt.payload.LoginRequest;
import com.example.jwt.payload.SignupRequest;
import com.example.jwt.repository.RoleRepository;
import com.example.jwt.repository.UserRepository;
import com.example.jwt.response.MessageResponse;
import com.example.jwt.security.JwtProvider;
//import com.example.jwt.service.UserService;
import com.example.jwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.HashSet;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private UserService userService;

    @Autowired
    public AuthenticationController(UserService userService) {
        this.userService = userService;
    }

    @RequestMapping(path = "/login", method = RequestMethod.POST)
    public ResponseEntity<?> authenticate(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.login(loginRequest);
    }

    @RequestMapping(value = "/signup", method = RequestMethod.POST)
    public ResponseEntity<?> createUser(@Valid @RequestBody SignupRequest signupRequest) {
        return userService.signup(signupRequest);
    }
}