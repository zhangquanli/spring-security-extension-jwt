package com.github.zhangquanli.security.sms.web.authentication;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processes an authentication form submission.
 */
public class SmsAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    private String mobileParameter = "mobile";
    private String codeParameter = "code";

    protected SmsAuthenticationFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: "
                    + request.getMethod());
        }
        String mobile = obtainMobile(request);
        mobile = (mobile != null) ? mobile : "";
        mobile = mobile.trim();
        String code = obtainCode(request);
        
        return null;
    }

    public void setMobileParameter(String mobileParameter) {
        this.mobileParameter = mobileParameter;
    }

    public void setCodeParameter(String codeParameter) {
        this.codeParameter = codeParameter;
    }

    private String obtainMobile(HttpServletRequest request) {
        return request.getParameter(mobileParameter);
    }

    private String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }
}
