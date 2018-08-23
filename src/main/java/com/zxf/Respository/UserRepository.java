package com.zxf.Respository;


import com.zxf.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author zxf
 * @date 2018/8/21 15:24
 */

public interface UserRepository extends JpaRepository<User, Integer> {
    //按名查找，需要一个联合查询
    User findByUsername(String username);
}
