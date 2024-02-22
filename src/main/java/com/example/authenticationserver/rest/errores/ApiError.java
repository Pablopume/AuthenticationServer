package com.example.authenticationserver.rest.errores;


import java.time.LocalDateTime;

public record ApiError(String message, LocalDateTime timestamp) {

}
