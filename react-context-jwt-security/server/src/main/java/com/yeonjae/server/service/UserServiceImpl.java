package com.yeonjae.server.service;

import com.yeonjae.server.dto.UserAuth;
import com.yeonjae.server.dto.Users;
import com.yeonjae.server.mapper.UserMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private UserMapper userMapper;

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
        // 아이디 패스워드로 인증 요청 토큰 생성
        UsernamePasswordAuthenticationToken token
                = new UsernamePasswordAuthenticationToken(username, password);

        // 토큰에 요청정보를 등록함
        token.setDetails(new WebAuthenticationDetails(request));

        // 토큰을 이용하여 인증 요청 - 로그인
        Authentication authentication = authenticationManager.authenticate(token);
        log.info("인증 여부 : " + authentication.isAuthenticated());

        User authUser = (User) authentication.getPrincipal();
        log.info("인증된 사용자 아이디 : " + authUser.getUsername());

        // 시큐리티 컨텍스트에 인증된 사용자를 등록함
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    @Override
    public int update(Users user) throws Exception {
        String userPw = user.getUserPw();
        String encodedPw = passwordEncoder.encode(userPw);
        user.setUserPw(encodedPw);
        int result = userMapper.update(user);
        return result;
    }

    @Override
    public int delete(String userId) throws Exception {
        return userMapper.delete(userId);
    }
}
