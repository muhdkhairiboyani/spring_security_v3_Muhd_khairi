package com.example.springsecurity.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Entity
@Table(name = "users")
@AllArgsConstructor
@NoArgsConstructor
@Getter                             // Lombok generated getters (avoid @Data for entities; performance issues)
@Setter                             // Lombok generated setters (avoid @Data for entities; performance issues)
// @ToString(exclude = "password")  // Old way: don't print passwords in logs!
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    @NotBlank(message = "Username cannot be blank.")
    private String userName;

    @Column(nullable = false, unique = true)
    @Email(regexp = "[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,3}",
            flags = Pattern.Flag.CASE_INSENSITIVE,
            message = "email is invalid.")
    @NotBlank(message = "email cannot be blank.")
    private String email;

    @ToString.Exclude                                      // Precision (field level): Prevents passwords from being printed
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) // Hide password in responses
    @Column(nullable = false)
    @NotBlank(message = "Password cannot be blank.")
    private String password;

    @Column(nullable = false)
    @CreationTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime createdDateTime;

    @Column(nullable = false)
    @UpdateTimestamp
    @Temporal(TemporalType.TIMESTAMP)
    private LocalDateTime updatedDateTime;

    @Lob
    @Column
    private String userBio;

    @Column
    private String userProfileImage;

    @Column(name="role", nullable = false)
    @Enumerated(EnumType.STRING)
    @NotNull(message = "Role cannot be blank.")
    private EnumRole role = EnumRole.USER;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    public String getUserName() {   // this.userName getter returns the object's userName
        return userName;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {   // UserDetails.getUserName treats the email as the username
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    /**
     *********************************************************************
        @Builder eradicates overloading constructors
        - Implement a Builder Pattern to chain syntax at instantiation
        - The constructor is created with only the fields for the builder
        - Note: Place @Builder here instead of at the top of the class
     *********************************************************************
        Example of using the builder pattern:
        User user = User.builder()
                .userName("John")
                .email("john@email.com")
                .role(EnumRole.ADMIN)
                .build();
     *********************************************************************
    */
    @Builder
    public User(String userName,
                String email,
                String password,
                EnumRole role,
                String userBio,
                String userProfileImage)
    {
        this.userName = userName;
        this.email = email;
        this.password = password;
        this.role = (role == null) ? EnumRole.USER : role;
        this.userBio = userBio;
        this.userProfileImage = userProfileImage;
    }

}
