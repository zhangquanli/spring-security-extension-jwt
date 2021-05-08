package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.sms.SmsAuthenticationFilter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;

/**
 * 短信登录配置
 */
public final class SmsLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractJwtAuthenticationFilterConfigurer<H, SmsLoginConfigurer<H>, SmsAuthenticationFilter> {

    public SmsLoginConfigurer() {
        super(new SmsAuthenticationFilter(), "/sms_login");
        mobileParameter("mobile");
        codeParameter("code");
    }

    /**
     * The HTTP parameter to look for the mobile when performing authentication. Default
     * is "mobile".
     *
     * @param mobileParameter the HTTP parameter to look for the mobile when
     *                        performing authentication
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public SmsLoginConfigurer<H> mobileParameter(String mobileParameter) {
        getAuthenticationFilter().setMobileParameter(mobileParameter);
        return this;
    }

    /**
     * The HTTP parameter to look for the code when performing authentication. Default
     * is "code".
     *
     * @param codeParameter the HTTP parameter to look for the code when
     *                      performing authentication
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public SmsLoginConfigurer<H> codeParameter(String codeParameter) {
        getAuthenticationFilter().setCodeParameter(codeParameter);
        return this;
    }
}
