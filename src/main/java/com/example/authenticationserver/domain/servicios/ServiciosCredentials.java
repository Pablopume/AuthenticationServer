package com.example.authenticationserver.domain.servicios;


import com.example.authenticationserver.data.modelo.CredentialsEntity;
import com.example.authenticationserver.data.repository.CredentialsRepository;
import com.example.authenticationserver.domain.modelo.Credentials;
import com.example.authenticationserver.domain.modelo.CredentialsRegister;
import com.example.authenticationserver.domain.modelo.LoginToken;
import com.example.authenticationserver.domain.modelo.exceptions.Exception401;
import com.example.authenticationserver.domain.modelo.mappers.CredentialsMapper;
import com.example.authenticationserver.security.KeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;


import java.util.Date;

@Service
public class ServiciosCredentials {

    private final CredentialsMapper credentialsMapper;
    private final CredentialsRepository credentialsRepository;
    private final PasswordEncoder passwordEncoder;
    private final KeyProvider keyProvider;
    private final AuthenticationManager authenticationManager;

    public ServiciosCredentials(CredentialsMapper credentialsMapper, CredentialsRepository credentialsRepository, PasswordEncoder passwordEncoder, KeyProvider keyProvider, AuthenticationManager authenticationManager) {
        this.credentialsMapper = credentialsMapper;

        this.credentialsRepository = credentialsRepository;
        this.passwordEncoder = passwordEncoder;

        this.keyProvider = keyProvider;
        this.authenticationManager = authenticationManager;
    }


    public Boolean register(CredentialsRegister credentials) {
        credentials.setPassword(passwordEncoder.encode(credentials.getPassword()));
        CredentialsEntity credentialsEntity =credentialsMapper.toCredentialsEntity(credentials);
        credentialsEntity.setRol("USER");
        credentialsRepository.save(credentialsEntity);
        return true;
    }



    public LoginToken doLogin(String user, String password) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user, password));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        if(authentication.isAuthenticated()) {
            String accessToken = generateToken(user);
            String refreshToken = generateRefreshToken(user);
            return new LoginToken(accessToken, refreshToken);
        }
        //nunca va a llegar aquí ya que si no se autentica lanza la excepcion de hibernate, por eso devuelvo un null
        else {
            return null;
        }
    }

    private boolean validateToken(String refreshtoken) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(keyProvider.obtenerKeyPairUsuario("server").getPublic())
                    .build()
                    .parseClaimsJws(refreshtoken);

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
                .setExpiration(new Date(System.currentTimeMillis() + 300000))  // 300 seconds 300000
                .signWith(keyProvider.obtenerKeyPairUsuario("server").getPrivate())
                .compact();

    }

    public String generateRefreshToken(String nombre) {
        Credentials credentials = credentialsMapper.toCredentials(credentialsRepository.findByUsername(nombre));
        return Jwts.builder()
                .setSubject(credentials.getUsername())
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
