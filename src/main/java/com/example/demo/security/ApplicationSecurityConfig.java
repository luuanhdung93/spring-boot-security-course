package com.example.demo.security;

import static com.example.demo.security.ApplicationUserRole.STUDENT;

import com.example.demo.auth.ApplicationUserService;
import com.example.demo.jwt.JwtConfig;
import com.example.demo.jwt.JwtTokẹnVerifier;
import com.example.demo.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

  private final PasswordEncoder passwordEncoder;
  private final ApplicationUserService applicationUserService;

  private final UserDetailsService userDetailsService;

  private final SecretKey secretKey;

private final JwtConfig jwtConfig;

  @Autowired
  public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,
      ApplicationUserService applicationUserService,
      UserDetailsService userDetailsService,
      SecretKey secretKey,
      JwtConfig jwtConfig) {
    this.passwordEncoder = passwordEncoder;
    this.applicationUserService = applicationUserService;
    this.userDetailsService = userDetailsService;
    this.secretKey = secretKey;
    this.jwtConfig = jwtConfig;
  }
  //form login
  // @Override
//  protected void configure(HttpSecurity http) throws Exception {
//    http
//        .csrf().disable()
//        .authorizeRequests()
//        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
//        .antMatchers("/api/**").hasRole(STUDENT.name())
//        .anyRequest()
//        .authenticated()
//        .and()
//        .formLogin()
//        .loginPage("/login")
//        .permitAll()
//        .defaultSuccessUrl("/courses", true)
//        .usernameParameter("username")
//        .passwordParameter("password")
//        .and()
//        .rememberMe()
//        .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//        .rememberMeParameter("remember-me")
//        .key("uniqueAndSecret")
//        .and()
//        .logout()
//        .logoutUrl("/logout")
//        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
//        .clearAuthentication(true)
//        .invalidateHttpSession(true)
//        .deleteCookies("remember-me", "JSESSIONID")
//        .logoutSuccessUrl("/login");
////        .and()
////        .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
//  }

  //jwt
  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .csrf().disable()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
        .addFilterAfter(new JwtTokẹnVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
        .antMatchers("/api/**").hasRole(STUDENT.name())
        .anyRequest()
        .authenticated();

  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService);
    auth.authenticationProvider(daoAuthenticationProvider());
  }

  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(passwordEncoder);
    provider.setUserDetailsService(applicationUserService);
    return provider;
  }


}
