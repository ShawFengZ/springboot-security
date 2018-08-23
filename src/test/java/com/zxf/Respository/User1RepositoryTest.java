package com.zxf.Respository;

import com.zxf.entity.User;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@SpringBootTest
@RunWith(SpringRunner.class)
public class User1RepositoryTest {

    @Autowired
    UserRepository repository;
    @Test
    public void findByUserName() {
        User zhangsan = repository.findByUsername("zhangsan");
        System.out.println(zhangsan.toString());
    }
}