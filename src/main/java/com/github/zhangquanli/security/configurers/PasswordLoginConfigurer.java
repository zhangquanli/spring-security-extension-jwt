package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.password.PasswordAuthenticationFilter;
import com.github.zhangquanli.security.password.PasswordAuthenticationProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;

/**
 * 密码登录配置
 */
public final class PasswordLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractJwtAuthenticationFilterConfigurer<H, PasswordLoginConfigurer<H>, PasswordAuthenticationFilter> {

    public PasswordLoginConfigurer() {
        super(new PasswordAuthenticationFilter(), "/password_login");
        usernameParameter("username");
        passwordParameter("password");
    }

    /**
     * The HTTP parameter to look for the username when performing authentication. Default
     * is "username".
     *
     * @param usernameParameter the HTTP parameter to look for the username when
     *                          performing authentication
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public PasswordLoginConfigurer<H> usernameParameter(String usernameParameter) {
        getAuthenticationFilter().setUsernameParameter(usernameParameter);
        return this;
    }

    /**
     * The HTTP parameter to look for the password when performing authentication. Default
     * is "password".
     *
     * @param passwordParameter the HTTP parameter to look for the password when
     *                          performing authentication
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public PasswordLoginConfigurer<H> passwordParameter(String passwordParameter) {
        getAuthenticationFilter().setPasswordParameter(passwordParameter);
        return this;
    }

    @Override
    public void init(H http) {
        AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
        http.authenticationProvider(authenticationProvider);
        super.init(http);
    }

    private AuthenticationProvider getAuthenticationProvider(H http) {
        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
        PasswordAuthenticationProvider provider = new PasswordAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        return provider;
    }
}
