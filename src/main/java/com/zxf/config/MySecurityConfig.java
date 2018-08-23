package com.zxf.config;

import com.zxf.security.CustomUserService;
import com.zxf.util.MD5Util;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author zxf
 * @date 2018/8/21 13:10
 */
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

    //注册UserDetailsService 的bean
    @Bean
    public UserDetailsService customUserService(){
        return new CustomUserService();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //super.configure(http);

        //定制请求的授权规则
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");

        //开启自动配置的登录功能，如果没有登录权限，就到登录页面
        http.formLogin().usernameParameter("user").passwordParameter("pwd").loginPage("/userlogin");
        //1. 自动到/login登陆页
        //2. 重定向到/login?error页面
        //3. 更多详细功能
        //4. 默认post形式的 /login表示处理登录
        //5. 一旦定制loginpage, 那么loginpage的post请求就是登录


        //开启自动配置的注销功能
        http.logout().logoutSuccessUrl("/");//注销成功来到首页
        //1. 访问/logout表示用户注销，清空session
        //2. 注销成功会返回/login?logout

        //开启自动配置的记住我功能
        http.rememberMe().rememberMeParameter("remember");
        //14天内访问cookie可以自动
        //注销会删除那个cookie
    }

    //定义认证规则
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //super.configure(auth);
        //账号密码放在内存中
        /*auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2")
            .and()
            .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP3");*/
        //从数据库访问
        auth.userDetailsService(customUserService()).passwordEncoder(new PasswordEncoder() {

            //加密
            @Override
            public String encode(CharSequence rawPassword) {
                return MD5Util.encode((String) rawPassword);
            }

            //从数据库取出密码后比较
            @Override
            public boolean matches(CharSequence rawPassword, String encodePassword) {
                //将加密后的密码存放的数据库中，在注册的时候要记得
                return encodePassword.equals(MD5Util.encode((String)rawPassword));
            }
        });
    }
}
