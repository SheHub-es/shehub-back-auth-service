package es.shehub.auth_service.exceptions;

import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

@ControllerAdvice
public class ShehubResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(ShehubException.class)
    public ResponseEntity<BodyErrorMessage> handleShehubException(ShehubException exception) {
        HttpStatus httpStatus = exception.getHttpStatus() != null ? 
                exception.getHttpStatus() : HttpStatus.BAD_REQUEST;
        return buildErrorResponse(httpStatus, exception.getMessage());
    }

    // Optional: fallback for unexpected DB issues
    @ExceptionHandler(DataAccessException.class)
    public ResponseEntity<BodyErrorMessage> handleDataAccess(DataAccessException exception) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                "Error interno al acceder a la base de datos.");
    }

    // Optional: specific handler for login failures
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<BodyErrorMessage> handleBadCredentials(BadCredentialsException exception) {
        return buildErrorResponse(HttpStatus.UNAUTHORIZED, "Credenciales incorrectas.");
    }

    // Global fallback
    @ExceptionHandler(Exception.class)
    public ResponseEntity<BodyErrorMessage> handleUnexpected(Exception exception) {
        return buildErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR,
                "Error inesperado del servidor: " + exception.getMessage());
    }

    private ResponseEntity<BodyErrorMessage> buildErrorResponse(HttpStatus status, String message) {
        BodyErrorMessage body = new BodyErrorMessage(status.value(), message);
        return new ResponseEntity<>(body, status);
    }
}