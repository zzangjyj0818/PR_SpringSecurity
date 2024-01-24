package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

// 스프링 구성 클래스임을 명시
@Configuration
public class ProjectConfig extends WebSecurityConfigurerAdapter {
    // 스프링 컨텍스트에 등록하기 위해
    // 빈 어노테이션 사용
    @Bean
    public UserDetailsService userDetailsService(){
        var userDetailService =
                new InMemoryUserDetailsManager();

        var user = User.withUsername("john")
                .password("12345")
                .authorities("read")
                .build();
        userDetailService.createUser(user);
        return userDetailService;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        // 이 경우에는 패스워드를 암호화하지 않는 케이스임.
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.httpBasic();
        // 모든 요청에 인증이 필요함
//        http.authorizeRequests().anyRequest().authenticated();
        // 인증 없이 요청 가능
        http.authorizeRequests().anyRequest().permitAll();
    }
}
