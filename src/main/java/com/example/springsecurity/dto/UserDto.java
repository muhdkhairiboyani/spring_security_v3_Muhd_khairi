package com.example.springsecurity.dto;


import com.example.springsecurity.model.EnumRole;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Builder                                                    // Lombok builder pattern, resolving the "Constructor Nightmare"
public class UserDto {

    private String userName;
    private String email;
    @ToString.Exclude                                       // Precision (field level): Prevents passwords from being printed
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)  // Hide password in responses
    private String password;
    private String userBio;
    private String userProfileImage;
    private EnumRole role;
    private String token;
    private String refreshToken;
    private Long expirationTime;
    private String message;

    /*
    @Builder eradicates overloading constructors
    Implements a Builder Pattern to chain syntax at instantiation
    Example:
    UserDto dto = UserDto.builder()
            .userName("John")
            .email("john@email.com")
            .role(EnumRole.ADMIN)
            .build();
    */

}
