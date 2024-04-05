package com.kafka.carusers.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserResponse {
    private Long id;
    private String firstName;
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String lastName;
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String email;
    private String phoneNumber;
}
