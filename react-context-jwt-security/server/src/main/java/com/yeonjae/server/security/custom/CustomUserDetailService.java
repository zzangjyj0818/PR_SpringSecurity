package com.yeonjae.server.security.custom;

import com.yeonjae.server.dto.CustomUser;
import com.yeonjae.server.dto.Users;
import com.yeonjae.server.mapper.UserMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CustomUserDetailService implements UserDetailsService {
    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("login - loadUserByUsername : " + username);

        Users user = userMapper.login(username);

        if(user == null){
            log.info("Not Exist User");
            throw new UsernameNotFoundException("Not Exist User : " + user);
        }

        log.info("Exist User In DataBase : " + user.toString());

        // Users -> CustomUser
        CustomUser customUser = new CustomUser(user);

        log.info("customUser : " + customUser.toString());
        return customUser;
    }
}
