package com.example.demo.jwt;

import com.google.common.net.HttpHeaders;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.jwt")
@Data
public class JwtConfig {

  private String secretKey;
  private String tokenPrefix;
  private Integer tokenExpirationAfterDays;


  public String getAuthorizationHeader() {
    return HttpHeaders.AUTHORIZATION;
  }

}
