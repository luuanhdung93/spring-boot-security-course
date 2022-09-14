package com.example.demo.dao;

import static com.example.demo.security.ApplicationUserRole.ADMIN;
import static com.example.demo.security.ApplicationUserRole.ADMINTRAINEE;
import static com.example.demo.security.ApplicationUserRole.STUDENT;

import com.example.demo.auth.ApplicationUser;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
@Repository()
public class FakeApplicationUserDaoImpl implements ApplicationUserDao {

  private final PasswordEncoder passwordEncoder;

  @Autowired
  public FakeApplicationUserDaoImpl(PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
    return getApplicationUser()
        .stream()
        .filter(applicationUser -> username.equals((applicationUser.getUsername())))
        .findFirst();
  }

  private List<ApplicationUser> getApplicationUser() {
    List<ApplicationUser> applicationUsers = List.of(
        new ApplicationUser(
            "dungla10",
            passwordEncoder.encode("123"),
            STUDENT.getGrantedAuthorities(),
            true,
            true,
            true,
            true

        ),
        new ApplicationUser(
            "ngoc96",
            passwordEncoder.encode("123"),
            ADMINTRAINEE.getGrantedAuthorities(),
            true,
            true,
            true,
            true

        ),
        new ApplicationUser(
            "luuanhdung93",
            passwordEncoder.encode("123"),
            ADMIN.getGrantedAuthorities(),
            true,
            true,
            true,
            true

        )
    );
    return applicationUsers;
  }
}
