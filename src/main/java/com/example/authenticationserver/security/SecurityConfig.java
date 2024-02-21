package com.example.authenticationserver.security;


import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(securedEnabled = true,
        prePostEnabled = true,
        jsr250Enabled = true
)

@RequiredArgsConstructor
public class SecurityConfig {
    private static final String[] AUTH_WHITE_LIST = {
            "/v3/api-docs/**",
            "/swagger-ui/**",
            "/v2/api-docs/**",
            "/swagger-resources/**"
    };
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return     http
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authorizeRequests ->
                        authorizeRequests
                                .requestMatchers("/login").permitAll()
                                .requestMatchers("/refreshToken").permitAll()
                                .requestMatchers("/credentials").permitAll()
                                .requestMatchers("/swagger-ui/**").permitAll()
                                .requestMatchers(AUTH_WHITE_LIST).permitAll()
                                .anyRequest().authenticated()
                ).build();


    }


}
