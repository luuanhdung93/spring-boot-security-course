package com.example.demo.jwt;

import lombok.Data;

@Data
public class UsernameAndPasswordAuthenticationRequest {
  private String username;
  private String password;

}
