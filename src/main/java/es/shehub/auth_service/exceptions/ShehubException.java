package es.shehub.auth_service.exceptions;

import org.springframework.http.HttpStatus;

import lombok.Getter;

@Getter
public class ShehubException extends RuntimeException {
    private HttpStatus httpStatus;

    public ShehubException(String message) {
        super(message);
    }

    public ShehubException(String message, HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
    }
}
