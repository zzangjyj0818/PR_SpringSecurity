package com.yeonjae.server.mapper;

import com.yeonjae.server.dto.UserAuth;
import com.yeonjae.server.dto.Users;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {
    public int insert(Users user) throws Exception;
    public Users select(int userNo) throws Exception;
    public Users login(String username);
    public int insertAuth(UserAuth userAuth) throws Exception;
    public int update(Users user) throws Exception;
    public int delete(String userId) throws Exception;
}
