package com.example.authenticationserver.domain.modelo.mappers;

import com.example.authenticationserver.data.modelo.CredentialsEntity;
import com.example.authenticationserver.domain.modelo.Credentials;
import com.example.authenticationserver.domain.modelo.CredentialsRegister;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface CredentialsMapper {

Credentials toCredentials(CredentialsEntity credentialsEntity);
CredentialsEntity toCredentialsEntity(Credentials credentials);

CredentialsEntity toCredentialsEntity(CredentialsRegister credentialsRegister);
}
