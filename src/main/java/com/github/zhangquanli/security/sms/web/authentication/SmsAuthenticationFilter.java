package com.github.zhangquanli.security.sms.web.authentication;

import com.github.zhangquanli.security.sms.authentication.SmsAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Processes an authentication form submission.
 */
public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private String mobileParameter = "mobile";
    private String codeParameter = "code";
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER =
            new AntPathRequestMatcher("/login", "POST");

    public SmsAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public SmsAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: "
                    + request.getMethod());
        }

        String mobile = obtainMobile(request);
        mobile = (mobile != null) ? mobile : "";
        mobile = mobile.trim();
        String code = obtainCode(request);
        code = (code != null) ? code : "";

        SmsAuthenticationToken authRequest = new SmsAuthenticationToken(mobile, code);
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

    private String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    private String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

    private void setDetails(HttpServletRequest request, SmsAuthenticationToken authRequest) {
        authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
    }
}
