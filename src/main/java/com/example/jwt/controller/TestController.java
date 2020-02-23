package com.example.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/test")
public class TestController {

    @RequestMapping(path = "/all", method = RequestMethod.GET)
    public String allAccess(){
        return "Public Content.";
    }

    @RequestMapping(path = "/user", method = RequestMethod.GET)
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess(){
        return "User Content.";
    }

    @RequestMapping(path = "/moderator", method = RequestMethod.GET)
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess(){
        return "Moderator Content.";
    }

    @RequestMapping(path = "/admin", method = RequestMethod.GET)
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess(){
        return "Admin Content.";
    }
}
