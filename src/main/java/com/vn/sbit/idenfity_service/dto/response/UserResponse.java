package com.vn.sbit.idenfity_service.dto.response;

import com.vn.sbit.idenfity_service.entity.Role;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDate;
import java.util.Set;

@Data
@NoArgsConstructor //constructor null
@AllArgsConstructor // constuctor đầy đủ thuộc tính
@FieldDefaults(level = AccessLevel.PRIVATE)
public class UserResponse {
     String id;

     String userName;

//     String passWord;

     String firstName;

     String lastName;

     LocalDate dob;

     Set<RoleResponse> roles;

}
