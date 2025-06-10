package es.shehub.auth_service.models.dtos.requests;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class UpdateStatusRequestDTO {
    private final String status;
}
