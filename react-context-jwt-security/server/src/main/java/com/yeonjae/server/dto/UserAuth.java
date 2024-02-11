package com.yeonjae.server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class UserAuth {
    private int authNo;
    private String userId;
    private String auth;

    public UserAuth(String userId, String auth) {
        this.userId = userId;
        this.auth = auth;
    }
}
