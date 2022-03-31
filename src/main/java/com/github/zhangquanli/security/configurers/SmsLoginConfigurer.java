//package com.github.zhangquanli.security.configurers;
//
//import com.github.zhangquanli.security.sms.SmsAuthenticationFilter;
//import com.github.zhangquanli.security.sms.SmsAuthenticationProvider;
//import com.github.zhangquanli.security.sms.VerifiedCodeRepository;
//import org.springframework.context.ApplicationContext;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
//import org.springframework.security.core.userdetails.UserDetailsService;
//
///**
// * 短信登录配置
// */
//public final class SmsLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
//        AbstractJwtAuthenticationFilterConfigurer<H, SmsLoginConfigurer<H>, SmsAuthenticationFilter> {
//
//    public SmsLoginConfigurer() {
//        super(new SmsAuthenticationFilter(), "/sms_login");
//        mobileParameter("mobile");
//        codeParameter("code");
//    }
//
//    /**
//     * The HTTP parameter to look for the mobile when performing authentication. Default
//     * is "mobile".
//     *
//     * @param mobileParameter the HTTP parameter to look for the mobile when
//     *                        performing authentication
//     * @return the {@link PasswordLoginConfigurer} for additional customization
//     */
//    public SmsLoginConfigurer<H> mobileParameter(String mobileParameter) {
//        getAuthenticationFilter().setMobileParameter(mobileParameter);
//        return this;
//    }
//
//    /**
//     * The HTTP parameter to look for the code when performing authentication. Default
//     * is "code".
//     *
//     * @param codeParameter the HTTP parameter to look for the code when
//     *                      performing authentication
//     * @return the {@link PasswordLoginConfigurer} for additional customization
//     */
//    public SmsLoginConfigurer<H> codeParameter(String codeParameter) {
//        getAuthenticationFilter().setCodeParameter(codeParameter);
//        return this;
//    }
//
//    @Override
//    public void init(H http) {
//        AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
//        http.authenticationProvider(authenticationProvider);
//        super.init(http);
//    }
//
//    private AuthenticationProvider getAuthenticationProvider(H http) {
//        ApplicationContext applicationContext = http.getSharedObject(ApplicationContext.class);
//        UserDetailsService userDetailsService = applicationContext.getBean(UserDetailsService.class);
//        VerifiedCodeRepository verifiedCodeRepository = applicationContext.getBean(VerifiedCodeRepository.class);
//        SmsAuthenticationProvider provider = new SmsAuthenticationProvider();
//        provider.setUserDetailsService(userDetailsService);
//        provider.setVerifiedCodeRepository(verifiedCodeRepository);
//        return provider;
//    }
//}
