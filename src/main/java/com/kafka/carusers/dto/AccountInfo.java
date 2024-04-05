package com.kafka.carusers.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountInfo {
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String firstName;
    //    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String lastName;
//    @NotEmpty
//    @Size(min = 3, message = "Last name can not be less than 3")
    private String email;
    //    @NotEmpty
//    @Size(min = 6, message = "Password should have at least 6 characters")
}
