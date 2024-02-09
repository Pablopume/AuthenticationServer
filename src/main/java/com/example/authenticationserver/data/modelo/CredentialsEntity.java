package com.example.authenticationserver.data.modelo;

import jakarta.persistence.Column;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;

public class CredentialsEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    private int id;
    @Column(name = "username", unique = true)
    private String username;

    @Column(name = "accesToken", length = 255)
    private String accesToken;
    @Column(name = "refreshToken", length = 255)
    private String refreshToken;
    @Column(name = "password")
    private String password;
    @Column(name = "rol")
    private String rol;
}
