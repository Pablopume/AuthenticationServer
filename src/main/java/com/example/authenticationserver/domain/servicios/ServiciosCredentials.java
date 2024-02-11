package com.example.authenticationserver.domain.servicios;


import com.example.authenticationserver.data.modelo.CredentialsEntity;
import com.example.authenticationserver.data.repository.CredentialsRepository;
import com.example.authenticationserver.domain.modelo.Credentials;
import com.example.authenticationserver.domain.modelo.LoginToken;
import com.example.authenticationserver.domain.modelo.exceptions.Exception401;
import com.example.authenticationserver.domain.modelo.exceptions.ExceptionLogin;
import com.example.authenticationserver.domain.modelo.mappers.CredentialsMapper;
import com.example.authenticationserver.security.KeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.Date;

@Service
public class ServiciosCredentials {

    private final CredentialsMapper credentialsMapper;
    private final CredentialsRepository credentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyProvider keyProvider;

    public ServiciosCredentials(CredentialsMapper credentialsMapper, CredentialsRepository credentialsRepository, PasswordEncoder passwordEncoder, KeyProvider keyProvider) {
        this.credentialsMapper = credentialsMapper;

        this.credentialsRepository = credentialsRepository;
        this.passwordEncoder = passwordEncoder;

        this.keyProvider = keyProvider;
    }


    public Credentials addCredentials(Credentials credentials) {

        credentials.setPassword(passwordEncoder.encode(credentials.getPassword()));
        credentialsRepository.save(credentialsMapper.toCredentialsEntity(credentials));

        return credentials;
    }


    // http://localhost:8080/PSP_JWT-1.0-SNAPSHOT/api/credentials/login?user=pabsermat@gmail.com&password=1234565675785858566548648645858548548458
    public LoginToken doLogin(String user, String password) {
        Credentials credentials = credentialsMapper.toCredentials(credentialsRepository.findByUsername(user));

        if (credentials.getPassword() != null && (passwordEncoder.matches(password, credentials.getPassword()))) {
            String accessToken = generateToken(credentials.getUsername());
            String refreshToken = generateRefreshToken(credentials.getUsername());
            return new LoginToken(accessToken, refreshToken);


        }
        else {
            throw new ExceptionLogin("Usuario o contraseña incorrectos");
        }
    }

    private boolean validateToken(String accessToken) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(keyProvider.obtenerKeyPairUsuario("server").getPublic())
                    .build()
                    .parseClaimsJws(accessToken);

            long expirationMillis = claimsJws.getBody().getExpiration().getTime();
            return System.currentTimeMillis() < expirationMillis;

        } catch (ExpiredJwtException e) {
            throw new Exception401("Token expirado");
        }
    }

    public String generateToken(String nombre) {

        Credentials credentials = credentialsMapper.toCredentials(credentialsRepository.findByUsername(nombre));
        return Jwts.builder()
                .setSubject(credentials.getUsername())
                .claim("rol", credentials.getRol())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 300000))  // 300 seconds
                .signWith(keyProvider.obtenerKeyPairUsuario("server").getPrivate())
                .compact();

    }

    public String generateRefreshToken(String nombre) {
        Credentials credentials = credentialsMapper.toCredentials(credentialsRepository.findByUsername(nombre));
        return Jwts.builder()
                .setSubject(credentials.getUsername())
                .claim("rol", credentials.getRol())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 60000000))
                .signWith(keyProvider.obtenerKeyPairUsuario("server").getPrivate())
                .compact();
    }

    public String refreshToken(String refreshToken) {
        if (validateToken(refreshToken)) {
            String username = Jwts.parserBuilder()
                    .setSigningKey(keyProvider.obtenerKeyPairUsuario("server").getPrivate())
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody()
                    .getSubject();
            return generateToken(username);
        }

        return null;
    }
}
