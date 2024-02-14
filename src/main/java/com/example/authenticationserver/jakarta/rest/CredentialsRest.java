package com.example.authenticationserver.jakarta.rest;


import com.example.authenticationserver.domain.modelo.Credentials;
import com.example.authenticationserver.domain.modelo.LoginToken;
import com.example.authenticationserver.domain.servicios.ServiciosCredentials;
import com.example.authenticationserver.jakarta.RestConstantes;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;


@RequiredArgsConstructor
@RestController

public class CredentialsRest {
    private final ServiciosCredentials serviciosCredentials;


    @PostMapping(RestConstantes.CREDENTIALS)
    public Credentials register(@RequestBody Credentials credentials) {
        return serviciosCredentials.register(credentials);
    }

    @GetMapping(RestConstantes.LOGIN)
    public LoginToken getLogin(@RequestParam(RestConstantes.USERMINUSC) String user, @RequestParam(RestConstantes.PASSWORD) String password) {

        return serviciosCredentials.doLogin(user, password);
    }


    @GetMapping(RestConstantes.REFRESH_TOKEN)
    public LoginToken refreshToken(@RequestParam(RestConstantes.REFRESH_TOKEN1) String refreshToken) {
        String newToken = serviciosCredentials.refreshToken(refreshToken);
        return new LoginToken(newToken, refreshToken);

    }


}
