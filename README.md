# spring-security-extension-jwt

本项目基于前后端分离和无状态的原则，对 Spring Security 进行扩展，以适应目前应用开发。项目有如下特点：

1. 使用 JWT 作为认证凭证，不再使用 session + cookie 的方案。
2. 后端服务不保存用户状态，通过 JWT 对用户进行认证，并使用 JWT 保存部分非敏感的用户信息。
3. 前端应该将用户登录后下发的 JWT 保存，并在需要用户认证接口中传入该参数。（在请求头中，使用 Authorization 携带）

# 使用本扩展

1. 支持 Java 8 和 Spring Boot 2.x.x
2. 在 pom.xml 文件中，引入 Spring Security 和 本扩展依赖

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    <version>2.4.5</version>
</dependency>
<dependency>
<groupId>com.github.zhangquanli</groupId>
<artifactId>spring-security-extension-jwt</artifactId>
<version>0.1.0</version>
</dependency>
```

# 配置本扩展

1. 简单密码登录和简单短信登录

PasswordLoginConfigurer 是用于配置密码登录的过滤器，SmsLoginConfigurer 是用于配置短信登录的过滤器，BearerTokenConfigurer
是用于配置用户认证的过滤器。以上三种配置类，提供了相当多的配置项，具体可以查看源码。

```java
import com.github.zhangquanli.security.configurers.BearerTokenConfigurer;
import com.github.zhangquanli.security.configurers.PasswordLoginConfigurer;
import com.github.zhangquanli.security.configurers.SmsLoginConfigurer;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 处理跨域请求
        http.cors();
        // 开启密码登录功能
        http.apply(new PasswordLoginConfigurer<>());
        // 开启短信登录功能
        http.apply(new SmsLoginConfigurer<>());
        // 开启用户认证功能
        http.apply(new BearerTokenConfigurer<>());
    }
}
```

2. 提供实现了 UserDetailsService 接口的 Bean
3. 如果使用了短信登录功能，还需要提供实现了 VerifiedCodeRepository 接口的 Bean

此接口用于本扩展获取短信验证码，其中 save 方法需要用户自行放入手机号和验证码，验证码的过期时间也需要用户自行实现。

```java
import com.github.zhangquanli.security.sms.VerifiedCodeRepository;
import net.jodah.expiringmap.ExpiringMap;
import org.springframework.context.annotation.Configuration;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@Configuration
public class MyVerifiedCodeRepository implements VerifiedCodeRepository {
    private final Map<String, String> data = ExpiringMap.builder()
            .expiration(5, TimeUnit.MINUTES).build();

    @Override
    public String load(String mobile) {
        return data.get(mobile);
    }

    @Override
    public void save(String mobile, String verifiedCode) {
        data.put(mobile, verifiedCode);
    }

    @Override
    public void remove(String mobile) {
        data.remove(mobile);
    }

    @Override
    public boolean contains(String mobile) {
        return data.containsKey(mobile);
    }
}
```
