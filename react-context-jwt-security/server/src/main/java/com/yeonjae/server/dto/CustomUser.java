package com.yeonjae.server.dto;

import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Data
public class CustomUser implements UserDetails {
    private Users user;

    public CustomUser(Users user) {
        this.user = user;
    }

    /**
     * 권한 getter 메서드
     * List<UserAuth> ---> Collection<SimpleGrantedAuthority> (auth) 권한만 넘김
     */

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<UserAuth> authList = user.getAuthList();
        return authList.stream()
                                    .map(auth -> new SimpleGrantedAuthority(auth.getAuth()))
                                    .collect(Collectors.toList());
    }

    @Override
    public String getPassword() {
        return user.getUserPw();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.getEnabled() == 0 ? false : true;
    }
}
