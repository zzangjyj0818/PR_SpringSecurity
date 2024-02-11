package com.yeonjae.server.service;

import com.yeonjae.server.dto.UserAuth;
import com.yeonjae.server.dto.Users;
import com.yeonjae.server.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    private PasswordEncoder passwordEncoder;
    private UserMapper userMapper;

    private AuthenticationManager authenticationManager;

    @Autowired
    public UserServiceImpl(PasswordEncoder passwordEncoder, UserMapper userMapper, AuthenticationManager authenticationManager) {
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.authenticationManager = authenticationManager;
    }

    /*
    * 1. 비밀번호 암호화
    * 2. 회원 등록
    * 3. 권한 등록
    * */
    @Override
    public int insert(Users user) throws Exception {
        String userPw = user.getUserPw();
        String encodedPw = passwordEncoder.encode(userPw);
        user.setUserPw(encodedPw);

        int result = userMapper.insert(user);

        if( result > 0 ){
            UserAuth userAuth = new UserAuth();
            userAuth.setUserId(user.getUserId());
            userAuth.setAuth("ROLE_USER"); // Basic Authorization
            result = userMapper.insertAuth(userAuth);
        }
        return result;
    }

    /*
        Select User
     */
    @Override
    public Users select(int userNo) throws Exception {
        return userMapper.select(userNo);
    }

    /*
     *
     */
    @Override
    public void login(Users user, HttpServletRequest request) throws Exception {
        String username = user.getUserId();
        String password = user.getUserPw();
        log.info("username : " + username);
        log.info("password : " + password);

        // AuthenticationManager
        // 인증을 관리하는 객체를 사용하여 인증 여부 확인
    }

    @Override
    public int update(Users user) throws Exception {
        return 0;
    }

    @Override
    public int delete(String userId) throws Exception {
        return 0;
    }
}
