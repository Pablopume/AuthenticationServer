package com.example.authenticationserver.security;


import com.example.authenticationserver.data.modelo.CredentialsEntity;
import com.example.authenticationserver.data.repository.CredentialsRepository;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

@Service
public class CustomUserDetailsService implements UserDetailsService {


    private final CredentialsRepository userRepository;

    public CustomUserDetailsService(CredentialsRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        CredentialsEntity user = userRepository.findByUsername(username);
if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }

        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .roles(
                        user.getRol()

                               )
                .build();

    }
}
