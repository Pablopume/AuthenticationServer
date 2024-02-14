package com.example.authenticationserver.data.repository;

import com.example.authenticationserver.data.modelo.CredentialsEntity;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialsRepository  extends ListCrudRepository<CredentialsEntity, Long> {
CredentialsEntity findByUsername(String username);

}
