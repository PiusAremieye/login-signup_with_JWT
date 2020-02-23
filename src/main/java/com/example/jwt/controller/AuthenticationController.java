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

//   private UserService userService;
//
//   @Autowired
//    public AuthenticationController(UserService userService){
//       this.userService = userService;
//   }

    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager authenticationManager;
    private JwtProvider jwtProvider;

    @Autowired
    public AuthenticationController(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtProvider jwtProvider){
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtProvider = jwtProvider;
    }

//   @RequestMapping(path = "/login", method = RequestMethod.POST)
//   public ResponseEntity<?> authenticate(@Valid @RequestBody LoginRequest loginRequest){
//       return userService.login(loginRequest);
//   }

   @RequestMapping(value = "/signup", method = RequestMethod.POST)
   public ResponseEntity<?> createUser(@Valid @RequestBody SignupRequest signupRequest){
       if (userRepository.existsByUsername(signupRequest.getUsername())){
           return ResponseEntity.badRequest().body(new MessageResponse("Error: Username already exists"));

       }
       if (userRepository.existsByEmail(signupRequest.getEmail())){
           return ResponseEntity.badRequest().body(new MessageResponse("Error: Email already exists"));
       }

       User user = new User(signupRequest.getUsername(), signupRequest.getEmail(), passwordEncoder.encode(signupRequest.getPassword()));
       Set<String> stringOfRoles = signupRequest.getRole();
       System.out.println(stringOfRoles);
       Set<Role> roles = new HashSet<>();

       if (stringOfRoles == null){
           Role userRole = roleRepository.findByName(EnumRole.ROLE_USER)
                   .orElseThrow(() -> new RuntimeException("Error: Role not found"));
           roles.add(userRole);
       }else{
           stringOfRoles.forEach(role ->{
               switch (role){
                   case "admin":
                       System.out.println("admin");
                       Role adminRole = roleRepository.findByName(EnumRole.ROLE_ADMIN)
                               .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                       roles.add(adminRole);
                       break;
                   case "mod":
                       System.out.println("mod");
                       Role moderatorRole = roleRepository.findByName(EnumRole.ROLE_MODERATOR)
                               .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                       roles.add(moderatorRole);
                       break;
                   default:
                       System.out.println("user");
                       Role userRole = roleRepository.findByName(EnumRole.ROLE_USER)
                               .orElseThrow(() -> new RuntimeException("Error: Role not found"));
                       roles.add(userRole);
               }
           });
       }

       user.setRoles(roles);
       userRepository.save(user);
       return ResponseEntity.ok(new MessageResponse("Signed up successfully"));
   }
}
