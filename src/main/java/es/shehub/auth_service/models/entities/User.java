package es.shehub.auth_service.models.entities;

import java.time.LocalDateTime;
import java.util.UUID;

import org.springframework.data.annotation.CreatedDate;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
@Entity
@Table(name = "users")
public class User {
    @Id 
    private UUID id;

    @Column(name = "email", length = 255,  nullable = false,  unique = true)
    private String email;

    @Column(name = "password", length = 60, nullable = true)
    private String password;

    @Column(name = "first_name", length = 20)
    private String firstName;

    @Column(name = "last_name", length = 20)
    private String lastName;

    @Column(name = "status", length = 20)
    private String status;

    @Column(name = "provider", length = 20)
    private String provider = "LOCAL";

    @CreatedDate
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "profile_completed")
    private boolean profileCompleted = false;

    @ManyToOne
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;

    @PrePersist
    public void prePersist() {

        id = (id == null) ? UUID.randomUUID() : id;
        createdAt = (createdAt == null) ? LocalDateTime.now() : createdAt;
    }
}
