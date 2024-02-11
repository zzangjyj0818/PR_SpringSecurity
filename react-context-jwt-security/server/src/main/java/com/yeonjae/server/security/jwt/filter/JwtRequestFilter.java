package com.yeonjae.server.security.jwt.filter;

import com.yeonjae.server.security.custom.JwtConstants;
import com.yeonjae.server.security.jwt.provider.JwtTokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public class JwtRequestFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtRequestFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     *
     * JWT 요청 필터
     * - Request > headers > Authrization (JWT)
     * - Checking JWT TOKEN Validate
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // 헤더에서 jwt 토큰을 가져옴
        String header = request.getHeader(JwtConstants.TOKEN_HEADER);
        log.info("authorization : " + header);

        // 로그인을 요청하는 경우에 다음 필터로 이동하게 됨.
        // 로그인을 요청하는 경우가 아닌 경우에는 로그인 관련 필터를 벗어남
        // 즉, 이 조건문은 jwt가 존재하지 않으면, 다음 필터로 넘어가게 됨.
        if(header == null || header.isEmpty()
                || !header.startsWith(JwtConstants.TOKEN_PREFIX)){
            filterChain.doFilter(request, response);
            return;
        }

        // 토큰이 존재하는 경우
        // Bearer 를 제거해줘야함.
        String jwt = header.replace(JwtConstants.TOKEN_PREFIX, "");

        // 토큰을 이용하여 해석 진행
        Authentication authentication = jwtTokenProvider.getAuthentication(jwt);

        // 토큰 유효성 검사
        if(jwtTokenProvider.validateToken(jwt)) {
            log.info("유효한 토큰");

            // 로그인
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }

        // 다음 필터.....
        filterChain.doFilter(request, response);
    }
}
