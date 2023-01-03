package com.io.javabrains.controller;

import com.io.javabrains.model.AuthenticationRequest;
import com.io.javabrains.model.AuthenticationResponse;
import com.io.javabrains.service.CustomUserDetailService;
import com.io.javabrains.util.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private CustomUserDetailService customUserDetailService;

    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("/hello")
    public String hello(){
        return "Hello, Welcome to JWT !!!";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> createAuthenticationToken(@RequestBody AuthenticationRequest request) throws Exception{
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUserName(),request.getPassword()));
        }catch (BadCredentialsException ex){
            System.out.println("BAD CREDENTIALS !!!!");
            throw new BadCredentialsException(" Incorrect login credentials !!!");
        }
        UserDetails userDetail= customUserDetailService.loadUserByUsername(request.getUserName());
        final String jwt= jwtUtil.generateToken(userDetail);
        return new ResponseEntity<>(new AuthenticationResponse(jwt), HttpStatus.OK);
    }
}
