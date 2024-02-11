package com.yeonjae.server.security.jwt.provider;

import com.yeonjae.server.dto.CustomUser;
import com.yeonjae.server.dto.UserAuth;
import com.yeonjae.server.dto.Users;
import com.yeonjae.server.mapper.UserMapper;
import com.yeonjae.server.prop.JwtProps;
import com.yeonjae.server.security.custom.JwtConstants;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * JWT 토큰 관련 기능을 제공해주는 클래스
 * 토큰 생성
 * 토큰 해석
 * 토큰 유효성 검사
 */
@Slf4j
@Component
public class JwtTokenProvider {
    /**
     * Generate Token
     */
    @Autowired
    private JwtProps jwtProps;
    @Autowired
    private UserMapper userMapper;
    public String createToken(int userNo, String userId, List<String> roles){
        String jwt = Jwts.builder()
                .signWith(getShakey(), Jwts.SIG.HS512)
                .header()
                .add("typ", JwtConstants.TOKEN_TYPE)
                .and()
                .expiration(new Date(System.currentTimeMillis() + 1000*60*60*24*10))
                .claim("uno", "" + userNo)
                .claim("uid", userId)
                .claim("rol", roles)
                .compact();

        log.info("JWT : " + jwt);
        return jwt;
    }

    /**
     *
     * 토큰 해석
     */
    public UsernamePasswordAuthenticationToken getAuthentication(String authHeader){
        if(authHeader == null || authHeader.isEmpty()) return null;

        try {
            // JWT 추출
            String jwt = authHeader.replace(JwtConstants.TOKEN_PREFIX, "");

            Jws<Claims> parsedToken = Jwts.parser()
                                        .verifyWith(getShakey())
                                        .build()
                                        .parseSignedClaims(jwt);
            log.info("parsedToken : " + parsedToken);

            String userNo = parsedToken.getPayload().get("uno").toString();
            int no = (userNo == null ? 0 : Integer.parseInt(userNo));
            log.info("UserNo : " + userNo);

            String userId = parsedToken.getPayload().get("uid").toString();
            log.info("userId : " + userId);

            Claims claims = parsedToken.getPayload();
            Object roles = claims.get("rol");
            log.info("roles : " + roles);

            if(userId == null || userId.isEmpty())
                return null;

            // 유저 정보 세팅
            Users user = new Users();
            user.setNo(no);
            user.setUserId(userId);

            List<UserAuth> authList = ((List<?>) roles)
                    .stream()
                    .map(auth -> new UserAuth(userId, auth.toString()))
                    .collect(Collectors.toList());

            user.setAuthList(authList);

            List<SimpleGrantedAuthority> authorities = ((List<?>) roles)
                    .stream()
                    .map(auth -> new SimpleGrantedAuthority( (String)auth) )
                    .collect(Collectors.toList());

            try {
                Users usersInfo = userMapper.select(no);
                if( usersInfo != null){
                    user.setName(usersInfo.getName());
                    user.setEmail(usersInfo.getEmail());
                }
            } catch (Exception e){
                log.error(e.getMessage());
                log.error("토큰 유효 -> DB 추가 정보 조회 시 오류");
            }
            UserDetails userDetails = new CustomUser(user);
            return new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        } catch (ExpiredJwtException exception) {
            log.warn("Request to parse expired JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (UnsupportedJwtException exception) {
            log.warn("Request to parse unsupported JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (MalformedJwtException exception) {
            log.warn("Request to parse invalided JWT : {} failed : {}", authHeader, exception.getMessage());
        } catch (IllegalArgumentException exception) {
            log.warn("Request to parse empty or null JWT : {} failed : {}", authHeader, exception.getMessage());
        }
        return null;
    }

    // 토큰 유효성 검사
    // - 만료 기간 검사
    public boolean validateToken(String jwt) {
        try {
            Jws<Claims> parsedToken = Jwts.parser()
                    .verifyWith(getShakey())
                    .build()
                    .parseSignedClaims(jwt);
            log.info("Token Expired Time : " + parsedToken.getPayload().getExpiration());

            Date exp = parsedToken.getPayload().getExpiration();

            // 만료기한과 현재 시간을 비교하여
            // 만료 기간을 검사함.
            return !exp.before(new Date());

        } catch (ExpiredJwtException exception) {
            log.error("Token Expired");
        } catch (JwtException exception) {
            log.error("Token Tampered");
        } catch (NullPointerException exception) {
            log.error("Token is null!");
        }
        return false;
    }
    private byte[] getSigningKey() {
        return jwtProps.getSecretKey().getBytes();
    }

    private SecretKey getShakey() {
        return Keys.hmacShaKeyFor(getSigningKey());
    }
}
