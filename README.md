# springboot-security
整合springboot和security

# Springboot默认支持

### 应用程序的两个主要区域是“认证”和“授权”，也是Spring Security的目标。

- 认证(Authentication)，是建立一个他声明的主体的过程(一个主体，一般指用户，设备或者可以在应用程序中执行动作的其他系统)。
- 授权(Authorization)，是指确定一个主体是否允许在你的应用程序执行一个动作的过程。为了抵达需要授权的店，主题身份已经由认证过程建立。

所有的安全框架都是这样的。


# 一、基本环境的搭建

### 1. 新建项目
不要选中secruity

### 2. 导入页面和controller
输入localhost:8080测试是否能跑通。

# 二、登录、认证、授权

### 1. 引入Spring Security
```
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### 2. 编写配置类
```
@EnableWebSecurity
public class MySecurityConfig extends WebSecurityConfigurerAdapter {
}
```

### 3. 控制请求的访问权限
```
@Override
protected void configure(HttpSecurity http) throws Exception {
    //super.configure(http);

    //定制请求的授权规则
    http.authorizeRequests().antMatchers("/").permitAll()
            .antMatchers("/level1/**").hasRole("VIP1")
            .antMatchers("/level2/**").hasRole("VIP2")
            .antMatchers("/level3/**").hasRole("VIP3");
}
```
### 4. 开启登录功能
```
//开启自动配置的登录功能，如果没有登录权限，就到登录页面
http.formLogin();
//1. 自动到/login登陆页
//2. 重定向到/login?error页面
//3. 更多详细功能
```
### 5. 定义认证规则
```
//定义认证规则
//定义认证规则
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //super.configure(auth);
    auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder()).withUser("zhangsan").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP1","VIP2")
        .and()
        .withUser("lisi").password(new BCryptPasswordEncoder().encode("123456")).roles("VIP3");
}
```
### 6. 关于密码的问题
Spring Security 无法登陆，报错：There is no PasswordEncoder mapped for the id “null”。

我一开始用的认证信息获取来源是内存获取——inMemoryAuthentication，代码如下：
```
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //inMemoryAuthentication 从内存中获取  
    auth.inMemoryAuthentication().withUser("user1").password("123456").roles("USER"); 
}
```
使用的是spring security自带的login页面，结果登陆的时候，用户名和密码正确也无法打开资源，还是停留在login页面。而且发现控制台报了异常——There is no PasswordEncoder mapped for the id “null”。  

网上百度了一下发现这是因为Spring security 5.0中新增了多种加密方式，也改变了密码的格式。  

要想我们的项目还能够正常登陆，需要修改一下configure中的代码。我们要将前端传过来的密码进行某种方式加密，spring security 官方推荐的是使用bcrypt加密方式。那么如何对密码加密呢，只需要在configure方法里面指定一下。

修改后是这样的：
```
protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    //inMemoryAuthentication 从内存中获取  
    auth.inMemoryAuthentication().passwordEncoder(new 
    BCryptPasswordEncoder()).withUser("user1").password(new 
    BCryptPasswordEncoder().encode("123456")).roles("USER");
}
```

在inMemoryAuthentication()后面多了".passwordEncoder(new BCryptPasswordEncoder())",这相当于登陆时用BCrypt加密方式对用户密码进行处理。以前的".password("123456")" 变成了 ".password(new BCryptPasswordEncoder().encode("123456"))" ，这相当于对内存中的密码进行Bcrypt编码加密。比对时一致，说明密码正确，允许登陆。

如果你用的是在数据库中存储用户名和密码，那么一般是要在用户注册时就使用BCrypt编码将用户密码加密处理后存储在数据库中。并且修改configure()方法，加入".passwordEncoder(new BCryptPasswordEncoder())"，保证用户登录时使用bcrypt对密码进行处理再与数据库中的密码比对。如下：
```
//注入userDetailsService的实现类
auth.userDetailsService(userService).passwordEncoder(new BCryptPasswordEncoder());
```

# 三、注销
### 1. 开启自动配置的注销功能
```
//开启自动配置的注销功能
http.logout().logoutSuccessUrl("/");//注销成功来到首页
//1. 访问/logout表示用户注销，清空session
//2. 注销成功会返回/login?logout
```
### 2. 欢迎页面写一个注销的表单
```
<form th:action="@{/logout}" method="post">
    <input type="submit" value="注销"/>
</form>
```

### 3. 在页面中根据登录状态的不同显示信息
1. 引入依赖
```
<!-- thymeleaf中使用security -->
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-springsecurity4</artifactId>
    <version>3.0.2.RELEASE</version>
</dependency>
```
2. 引入名称空间
```
xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity4"
```

3. 详细信息
```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org"
      xmlns:sec="http://www.thymeleaf.org/thymeleaf-extras-springsecurity4" >
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Insert title here</title>
</head>
<body>
<h1 align="center">欢迎光临武林秘籍管理系统</h1>
<div sec:authorize="!isAuthenticated()">
    <!--未认证的情况下-->
    <h2 align="center">游客您好，如果想查看武林秘籍 <a th:href="@{/login}">请登录</a></h2>
</div>
<div sec:authorize="isAuthenticated()">
    <!--认证了情况下-->
    <h2><span sec:authentication="name"></span>, 你好，您的角色有<span sec:authentication="principal.authorities"></span></h2>
    <form th:action="@{/logout}" method="post">
        <input type="submit" value="注销"/>
    </form>
</div>

<hr>

<div sec:authorize="hasRole('VIP1')">
    <h3>普通武功秘籍</h3>
    <ul>
        <li><a th:href="@{/level1/1}">罗汉拳</a></li>
        <li><a th:href="@{/level1/2}">武当长拳</a></li>
        <li><a th:href="@{/level1/3}">全真剑法</a></li>
    </ul>
</div>

<div sec:authorize="hasRole('VIP2')">
    <h3>高级武功秘籍</h3>
    <ul>
        <li><a th:href="@{/level2/1}">太极拳</a></li>
        <li><a th:href="@{/level2/2}">七伤拳</a></li>
        <li><a th:href="@{/level2/3}">梯云纵</a></li>
    </ul>
</div>

<div sec:authorize="hasRole('VIP3')">
    <h3>绝世武功秘籍</h3>
    <ul>
        <li><a th:href="@{/level3/1}">葵花宝典</a></li>
        <li><a th:href="@{/level3/2}">龟派气功</a></li>
        <li><a th:href="@{/level3/3}">独孤九剑</a></li>
    </ul>
</div>

</body>
</html>
```

# 四、rememberme

```
//开启自动配置的记住我功能
http.rememberMe();
//14天内访问cookie可以自动
//注销会删除那个cookie
```

# 五、自定义登录页面
### 1. 登录页面
```
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
	<h1 align="center">欢迎登陆武林秘籍管理系统</h1>
	<hr>
	<div align="center">
		<form th:action="@{/userlogin}" action="" method="post">
			用户名:<input name="user"/><br>
			密码:<input name="pwd"><br/>
			<input type="checkbox" name="remember">记住我<br/>
			<input type="submit" value="登录">
		</form>
	</div>
</body>
</html>
```

### 2. 配置项
```
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
```

# 五、从数据库取数据校验

### 数据库设计
- 用户表：User: id, username, password
- 角色表：Role: id, name
- 中间表：User_Role: id, user_id, role_id

### 实体
- 用户
```Java
@Data
@Entity
public class User implements UserDetails{

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String username;

    private String password;

    //指定联合查询策略
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "User_Role", joinColumns = {@JoinColumn(name = "user_id")}, inverseJoinColumns = {@JoinColumn(name = "role_id")})
    private List<Role> roles;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> auths = new ArrayList<>();
        List<Role> sysRoles = this.getRoles();
        for (Role role : this.getRoles()){
            auths.add(new SimpleGrantedAuthority(role.getName()));
        }
        return auths;
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
        return true;
    }
}
```

- 角色
```Java
@Data
@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String name;

}
```

### dao层
```
public interface UserRepository extends JpaRepository<User, Integer> {
    //按名查找，需要一个联合查询
    User findByUsername(String username);
}
```

### 工具：加密工具(可选默认的)
```Java
public class MD5Util {

    private static final String SALT = "tamboo";

    public static String encode(String password){
        password = password + SALT;
        MessageDigest md5 = null;
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        char[] charArray = password.toCharArray();
        byte[] byteArray = new byte[charArray.length];
        for (int i = 0; i < charArray.length; i++)
            byteArray[i] = (byte) charArray[i];
        byte[] md5Bytes = md5.digest(byteArray);
        StringBuffer hexValue = new StringBuffer();
        for (int i = 0; i < md5Bytes.length; i++) {
            int val = ((int) md5Bytes[i]) & 0xff;
            if (val < 16) {
                hexValue.append("0");
            }

            hexValue.append(Integer.toHexString(val));
        }
        return hexValue.toString();
    }

    public static void main(String[] args){
        System.out.println(MD5Util.encode("123456"));
    }
}
```
JWT注册时候，密码放进数据库，也是先加密再放进去。

### 新的认证规则
```Java
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
```

### CustomUserService
```Java
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
```

### 注意点
角色数据库中的数据要加一个ROLE_  
即：  
ROLE_VIP1  
ROLE_VIP2  
ROLE_VIP3


