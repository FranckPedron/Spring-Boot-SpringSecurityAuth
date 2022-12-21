package com.franckycorp.springsecurityauth.login.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
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
    public UserDetailService userDetailService(BCryptPasswordEncoder bCryptPasswordEncoder) {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        manager.createUser(User
                .withUsername("springuser")
                .password(bCryptPasswordEncoder.encode("spring123"))
                .roles("USER")
                .build());

        manager.createUser(User
                .withUsername("springadmin")
                .password(bCryptPasswordEncoder.encode("admin123"))
                .roles("ADMIN","USER")
                .build());

        return manager;
    }
}
