package com.github.zhangquanli.security.sms;

import com.github.zhangquanli.security.AbstractJwtAuthenticationProcessingFilter;
import com.github.zhangquanli.security.JwtAuthenticationFailureHandler;
import com.github.zhangquanli.security.JwtAuthenticationSuccessHandler;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 短信登录配置
 */
public class SmsAuthenticationFilter extends AbstractJwtAuthenticationProcessingFilter {
    private static final AntPathRequestMatcher DEFAULT_REQUEST_MATCHER =
            new AntPathRequestMatcher("/sms_login", "POST");
    private String mobileParameter = "mobile";
    private String codeParameter = "code";
    private boolean postOnly = true;

    public SmsAuthenticationFilter() {
        super(DEFAULT_REQUEST_MATCHER);
        setAuthenticationSuccessHandler(new JwtAuthenticationSuccessHandler());
        setAuthenticationFailureHandler(new JwtAuthenticationFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (postOnly && !request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: "
                    + request.getMethod());
        }
        String mobile = obtainMobile(request);
        mobile = (mobile != null) ? mobile : "";
        mobile = mobile.trim();
        String code = obtainCode(request);
        code = (code != null) ? code : "";
        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(mobile, code);
        // Allow subclasses to set the "details" property
        setDetails(request, authRequest);
        return getAuthenticationManager().authenticate(authRequest);
    }


    /**
     * Sets the parameter name which will be used to obtain the mobile from the login
     * request.
     *
     * @param mobileParameter the parameter mobile. Defaults to "mobile".
     */
    public void setMobileParameter(String mobileParameter) {
        this.mobileParameter = mobileParameter;
    }

    /**
     * Sets the parameter name which will be used to obtain the code from the login
     * request.
     *
     * @param codeParameter the parameter name. Defaults to "code".
     */
    public void setCodeParameter(String codeParameter) {
        this.codeParameter = codeParameter;
    }

    /**
     * Defines whether only HTTP POST requests will be allowed by this filter. If set to
     * true, and an authentication request is received which is not a POST request, an
     * exception will be raised immediately and authentication will not be attempted. The
     * <tt>unsuccessfulAuthentication()</tt> method will be called as if handling a failed
     * authentication.
     * <p>
     * Defaults to <tt>true</tt> but may be overridden by subclasses.
     */
    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    @Nullable
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

    /**
     * Provided so that subclasses may configure what is put into the authentication
     * request's details property.
     *
     * @param request     that an authentication request is being created for
     * @param authRequest the authentication request object that should have its details
     *                    set
     */
    protected void setDetails(HttpServletRequest request, SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }
}
