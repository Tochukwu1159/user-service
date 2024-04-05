package com.kafka.carusers.dto;

import lombok.Builder;
import lombok.Data;

import java.util.List;
@Data
@Builder
public class AllUserResponse {
    private String firstName;
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String lastName;

    private String phoneNumber;
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String email;
    //    @NotEmpty
}
