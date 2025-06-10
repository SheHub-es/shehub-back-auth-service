package es.shehub.auth_service.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import es.shehub.auth_service.models.dtos.requests.GoogleUserDTO;
import es.shehub.auth_service.models.dtos.requests.UserRegisterRequestDTO;
import es.shehub.auth_service.models.dtos.responses.UserDTO;
import es.shehub.auth_service.models.entities.User;

/**
 * Mapper interface to convert between User entity and User DTOs
 * using MapStruct.
 */
@Mapper(componentModel = "spring")
public interface UserMapper {

    /**
     * Maps a UserRegisterRequestDTO to a User entity.
     * 
     * Ignores fields that are generated or managed internally (id, createdAt, status, provider, role).
     * Sets profileCompleted to false by default.
     * 
     * @param dto the user registration request DTO
     * @return the User entity with mapped fields
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "provider", ignore = true)
    @Mapping(target = "profileCompleted", constant = "false")
    @Mapping(target = "role", ignore = true) 
    User toUser(UserRegisterRequestDTO dto);

    /**
     * Maps a User entity to a UserDTO.
     * 
     * Maps role.name from the entity to the role field in the DTO.
     * 
     * @param user the User entity
     * @return the UserDTO with mapped fields
     */
    @Mapping(source = "id", target = "id")
    @Mapping(source = "role.name", target = "role")
    UserDTO toUserDTO(User user);

    /**
     * Maps a GoogleUserDTO to a UserRegisterRequestDTO.
     * 
     * Ignores field password.
     * 
     * @param GoogleUserDTO the User entity
     * @return the UserDTO with mapped fields
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "status", constant = "PENDING")
    @Mapping(target = "profileCompleted", constant = "false")
    @Mapping(target = "password", ignore = true)
    @Mapping(target = "role", ignore = true) 
    User fromGoogleUser(GoogleUserDTO dto);
}
