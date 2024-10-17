package com.vn.sbit.idenfity_service.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.util.Set;


@Entity
@Data
@NoArgsConstructor //constructor null
@AllArgsConstructor // constructor full property
@FieldDefaults(level = AccessLevel.PRIVATE)
@Builder
public class Role {
    @Id
    String name; //tên role _vd admin

    String description;

    @ManyToMany //1 role có thể có nhiều chuc nang - vd admin crud và 1 chức năng có thể có nhiều role đc , vd create: user-manager-admin;
    Set<Permission> permissions; // vd chức năng : CRUD








}
