package com.github.zhangquanli.security.config.annotation.web.configurers;

import com.github.zhangquanli.security.jwt.JwtEncoder;
import com.github.zhangquanli.security.jwt.JwtEncoders;
import com.github.zhangquanli.security.password.web.authentication.PasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * 密码登录配置
 */
public final class PasswordLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractJwtAuthenticationFilterConfigurer<H, PasswordLoginConfigurer<H>, PasswordAuthenticationFilter> {
    private JwtEncoder jwtEncoder;

    public PasswordLoginConfigurer() {
        super(new PasswordAuthenticationFilter(), "/password_login");
        jwtEncoder(JwtEncoders.defaultJwtEncoder());
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

    /**
     * Specifies the {@link JwtEncoder} to use when jwt generates.
     *
     * @param jwtEncoder the {@link JwtEncoder}
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final PasswordLoginConfigurer<H> jwtEncoder(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
        getAuthenticationFilter().setJwtEncoder(jwtEncoder);
        return this;
    }

    @Override
    public void init(H http) {
        super.init(http);
        registerDefaultJwtEncoder(http);
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultJwtEncoder(H http) {
        SmsLoginConfigurer<H> smsLogin = http.getConfigurer(SmsLoginConfigurer.class);
        if (smsLogin != null) {
            smsLogin.jwtEncoder(jwtEncoder);
        }
    }
}
