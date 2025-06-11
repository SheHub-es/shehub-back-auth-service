package es.shehub.auth_service.mappers;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.Named;

import es.shehub.auth_service.models.dtos.requests.GoogleUserDTO;

import es.shehub.auth_service.models.dtos.requests.UserRegisterRequestDTO;
import es.shehub.auth_service.models.dtos.responses.FullUserDataDTO;
import es.shehub.auth_service.models.dtos.responses.ProfileUserDataDTO;

import es.shehub.auth_service.models.dtos.responses.UserProjectDataDTO;
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
     * Ignores fields that are generated or managed internally (id, createdAt,
     * status, provider, role).
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

    /**
     * Maps user data from both the User entity and the UserProjectDataDTO into a FullUserDataDTO.
     *
     * Combines profile information, role, and account metadata from the auth service
     * with extended user details like skills, tech roles, and availability from the user-project service.
     *
     * This method is typically used to prepare detailed user data for admin dashboards or comprehensive profile views.
     *
     * @param user        the User entity containing core account information
     * @param userProject the DTO containing extended user profile data
     * @return a FullUserDataDTO with merged data from both sources
     */
    @Mapping(target = "id", source = "user.id")
    @Mapping(target = "email", source = "user.email")
    @Mapping(target = "createdAt", source = "user.createdAt")
    @Mapping(target = "provider", source = "user.provider")
    @Mapping(target = "status", source = "user.status")
    @Mapping(target = "profileCompleted", source = "user.profileCompleted")
    @Mapping(target = "firstName", source = "user.firstName")
    @Mapping(target = "lastName", source = "user.lastName")
    @Mapping(target = "techRoles", source = "userProject.techRoles")
    @Mapping(target = "skills", source = "userProject.skills")
    @Mapping(target = "schools", source = "userProject.schools")
    @Mapping(target = "avatarLink", source = "userProject.avatarLink")
    @Mapping(target = "linkedinLink", source = "userProject.linkedinLink")
    @Mapping(target = "githubLink", source = "userProject.githubLink")
    @Mapping(target = "portfolioLink", source = "userProject.portfolioLink")
    @Mapping(target = "availabilityPerWeek", source = "userProject.availabilityPerWeek")
    @Mapping(target = "comments", source = "userProject.comments")
    @Mapping(target = "teamLead", source = "userProject.teamLead")
    @Mapping(target = "role", source = "user", qualifiedByName = "mapRoleName")
    FullUserDataDTO toFullUserDataDTO(User user, UserProjectDataDTO userProject);

    /**
     * Maps User entity and UserProjectDataDTO to a ProfileUserDataDTO.
     * 
     * Combines basic user information from the User entity with project-related details
     * from UserProjectDataDTO to build a complete profile data transfer object
     * suitable for user profile views.
     * 
     * Fields mapped include identification, contact info, profile status,
     * social links, availability, skills, roles, and team lead status.
     * The user's role is converted to a String using the custom mapRoleName method.
     * 
     * @param user        the User entity containing core user data
     * @param userProject the UserProjectDataDTO containing project-specific user info
     * @return a populated ProfileUserDataDTO representing the user's profile data
     */
    @Mapping(target = "id", source = "user.id")
    @Mapping(target = "email", source = "user.email")
    @Mapping(target = "profileCompleted", source = "user.profileCompleted")
    @Mapping(target = "firstName", source = "user.firstName")
    @Mapping(target = "lastName", source = "user.lastName")
    @Mapping(target = "techRoles", source = "userProject.techRoles")
    @Mapping(target = "skills", source = "userProject.skills")
    @Mapping(target = "schools", source = "userProject.schools")
    @Mapping(target = "avatarLink", source = "userProject.avatarLink")
    @Mapping(target = "linkedinLink", source = "userProject.linkedinLink")
    @Mapping(target = "githubLink", source = "userProject.githubLink")
    @Mapping(target = "portfolioLink", source = "userProject.portfolioLink")
    @Mapping(target = "availabilityPerWeek", source = "userProject.availabilityPerWeek")
    @Mapping(target = "comments", source = "userProject.comments")
    @Mapping(target = "teamLead", source = "userProject.teamLead")
    @Mapping(target = "role", source = "user", qualifiedByName = "mapRoleName")
    ProfileUserDataDTO toProfileUserDataDTO(User user, UserProjectDataDTO userProject);


    /**
     * Extracts the role name as a String from the User entity.
     *
     * Safely returns the role name if the role is not null, otherwise returns null.
     * Intended for use in MapStruct mappings where role is represented as a String.
     *
     * @param user the User entity containing a Role
     * @return the name of the role or null if no role is assigned
     */
    @Named("mapRoleName")
    default String mapRoleName(User user) {
        return user.getRole() != null ? user.getRole().getName() : null;
    }
}
