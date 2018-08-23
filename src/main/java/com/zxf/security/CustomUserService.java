package com.zxf.security;

import com.zxf.Respository.UserRepository;
import com.zxf.entity.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @author zxf
 * @date 2018/8/21 15:04
 */
@Service
@Slf4j
public class CustomUserService implements UserDetailsService {

    @Autowired
    private UserRepository repository;

    @Override
    public UserDetails loadUserByUsername(String username) {

        User user = repository.findByUsername(username);
        if (user == null){
            throw new UsernameNotFoundException("用户名不存在！");
        }
        log.info("【用户名】：{}",username);
        log.info("【密码】：{}",user.getPassword());
        /*List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role: user.getRoles()){
            authorities.add(new SimpleGrantedAuthority(role.getName()));
            log.info("【role的权限】{}",role.getName());
        }
        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);*/
        return user;
    }
}
