package com.example.authenticationserver.jakarta.rest;


import com.example.authenticationserver.domain.modelo.Credentials;
import com.example.authenticationserver.domain.modelo.LoginToken;
import com.example.authenticationserver.domain.servicios.ServiciosCredentials;
import com.example.authenticationserver.jakarta.RestConstantes;
import jakarta.ws.rs.core.Response;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;


@RequiredArgsConstructor
@RestController

public class CredentialsRest {
    private final ServiciosCredentials serviciosCredentials;


    @PostMapping(RestConstantes.CREDENTIALS)
    public Credentials addCredentials(@RequestBody Credentials credentials) {
        return serviciosCredentials.addCredentials(credentials);
    }

    @GetMapping(RestConstantes.LOGIN)
    public LoginToken getLogin(@RequestParam(RestConstantes.USERMINUSC) String user, @RequestParam(RestConstantes.PASSWORD) String password) {
        LoginToken result = serviciosCredentials.doLogin(user, password);

        return result;
    }


    @GetMapping(RestConstantes.REFRESH_TOKEN)
    public LoginToken refreshToken(@RequestParam(RestConstantes.REFRESH_TOKEN1) String refreshToken) {
        String newToken = serviciosCredentials.refreshToken(refreshToken);
        LoginToken loginToken = new LoginToken(newToken, refreshToken);
        return loginToken;

    }


}
