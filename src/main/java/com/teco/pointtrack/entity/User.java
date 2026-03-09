package com.teco.pointtrack.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.teco.pointtrack.entity.enums.AuthProvider;
import com.teco.pointtrack.entity.enums.Gender;
import com.teco.pointtrack.entity.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;
import lombok.experimental.SuperBuilder;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class User extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "full_name", length = 100)
    private String fullName;

    @Column(unique = true, length = 100)
    private String email;

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;

    @Column(name = "phone_number", length = 10, unique = true)
    private String phoneNumber;

    @Column(name = "citizen_id", length = 12, unique = true)
    private String citizenId;

    @Column(name = "date_of_birth")
    private LocalDate dateOfBirth;

    @Column(name = "avatar_url")
    private String avatarUrl;

    @Enumerated(EnumType.ORDINAL)
    @Column(columnDefinition = "TINYINT")
    private Gender gender;

    @Enumerated(EnumType.STRING)
    @Column(columnDefinition = "ENUM('ACTIVE', 'INACTIVE', 'BANNED', 'UNVERIFIED')")
    private UserStatus status;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @JsonIgnore
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider")
    @JsonIgnore
    private AuthProvider provider;
}
