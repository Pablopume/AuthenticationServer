package com.example.authenticationserver.domain.modelo;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class Credentials {
    private int id;
    private String username;

    private String password;
    private String rol;

}
