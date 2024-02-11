package com.yeonjae.server.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserAuth {
    private int authNo;
    private String userId;
    private String auth;
}
