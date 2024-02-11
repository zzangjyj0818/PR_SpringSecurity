package com.yeonjae.server.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
@EnableWebSecurity
// 필터 설정 및 인가 설정
/*
 * 필터 설정
 * JWT Request Filter -> JWT 토큰 해석
 * JWT Filter (Login) -> username & password -> JWT 토큰 생성
 *
 * 인가 설정
 * 정적자원은 모두가 접근할 수 있도록
 * /, /login 경로도 모두가 접근할 수 있도록
 * /user/** - USER, ADMIN
 * /admin/** - ADMIN
 */
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        log.info("Setting Security");

        http.formLogin(login -> login.disable());
        http.httpBasic(basic -> basic.disable());
        http.csrf(csrf -> csrf.disable());
        http.addFilterAt(null, null)
                .addFilterBefore(null, null);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
