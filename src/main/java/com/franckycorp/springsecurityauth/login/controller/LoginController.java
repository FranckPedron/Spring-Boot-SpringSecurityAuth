package com.franckycorp.springsecurityauth.login.controller;

import jakarta.annotation.security.RolesAllowed;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class LoginController {

    @RequestMapping("/**")
    @RolesAllowed("USER")
    public String getUser() {
        return "Welcome User";
    }

    @RequestMapping("/admin")
    @RolesAllowed("ADMIN")
    public String getAdmin() {
        return "Welcome Admin";
    }

    @RequestMapping("/*")
    public  String getGithub(Principal user) {
        return "Welcome " + user.getName();
    }
}
