package com.yeonjae.server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Users {
    private int no;
    private String userId;
    private String userPw;
    private String userPwCheck;
    private String name;
    private String email;
    private Date regDate;
    private Date updDate;
    private int enabled;

    List<UserAuth> authList;

}
