package com.yeonjae.server.security.jwt.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.parameters.P;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        // Filter URL 경로 설정 : /login
        setFilterProcessesUrl("/login");
    }

    /**
     * 인증을 시도하는 메서드 구현
     * /login 경로로 request 왔을때만...
     * 필터로 걸러서 인증을 시도함.
     * client -> filter (/login) -> server
     * username, password 로 인증 시도
     * 인증 성공 시, JWT 생성
     * 응답 헤더에 JWT 를 실어서 반환
     * 인증 실패 시, 헤더의 status 에 401(UNAUTHORIZED)을 담아서 반환
     */

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username =request.getParameter("username");
        String password =request.getParameter("password");

        log.info("username : " + username);
        log.info("password : " + password);

        // 사용자 인증정보 객체 생성
        Authentication authentication = new UsernamePasswordAuthenticationToken(username, password);
        authentication = authenticationManager.authenticate(authentication);

        log.info("인증 정보 " + authentication.isAuthenticated());

        if(!authentication.isAuthenticated()){
            log.info("인증 실패 : 아이디 또는 패스워드가 일치하지 않습니다.");
            response.setStatus(401); // UNAUTHORIZED (인증 실패)
        }
        // 사용자 인증(로그인)
        return authentication;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        super.successfulAuthentication(request, response, chain, authResult);
    }
}
