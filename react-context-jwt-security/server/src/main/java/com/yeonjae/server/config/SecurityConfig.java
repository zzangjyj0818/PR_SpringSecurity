package com.yeonjae.server.config;

import com.yeonjae.server.security.custom.CustomUserDetailService;
import com.yeonjae.server.security.jwt.filter.JwtAuthenticationFilter;
import com.yeonjae.server.security.jwt.filter.JwtRequestFilter;
import com.yeonjae.server.security.jwt.provider.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


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
@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private CustomUserDetailService customUserDetailService;
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        log.info("Setting Security");

        http.formLogin(login -> login.disable());
        http.httpBasic(basic -> basic.disable());
        http.csrf(csrf -> csrf.disable());
        http.addFilterAt(new JwtAuthenticationFilter(authenticationManager, jwtTokenProvider)
                        , UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtRequestFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);

        // 인가 설정
        // 상위 경로 -> 하위 경로 순으로 인가 설정을 해줘야함
        http.authorizeHttpRequests( authorizationManagerRequestMatcherRegistry ->
                authorizationManagerRequestMatcherRegistry
                        .requestMatchers(PathRequest.toStaticResources().atCommonLocations())
                        .permitAll()
                        .requestMatchers("/", "/login")
                        .permitAll()
                        .requestMatchers("/user/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
        );

        // 인증 방식 설정
        // 인메모리 방식 & JDBC 방식
        // JDBC 방식 -> 커스텀 (UserDetailService) -> 사용자에 대한 비지니스 로직 작성
        http.userDetailsService(customUserDetailService);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // AuthenticationManager 빈 등록
    @Bean
    public AuthenticationManager authenticationManager
            (AuthenticationConfiguration authenticationConfiguration) throws Exception {
        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
        return authenticationManager;
    }
}
