package com.franckycorp.springsecurityauth.login.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SpringSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin").hasAnyRole("ADMIN")
                .requestMatchers("/user").hasRole("USER")
                .anyRequest().authenticated()
                .and()
        ).formLogin();
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(User
                .withUsername("springuser")
                .password(passwordEncoder().encode("spring123"))
                .roles("USER")
                .build());

        manager.createUser(User
                .withUsername("springadmin")
                .password(passwordEncoder().encode("admin123"))
                .roles("ADMIN","USER")
                .build());

        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
