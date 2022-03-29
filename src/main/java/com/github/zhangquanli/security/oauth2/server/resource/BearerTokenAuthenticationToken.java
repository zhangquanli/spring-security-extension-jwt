package com.github.zhangquanli.security.oauth2.server.resource;

import com.github.zhangquanli.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * An {@link Authentication} that contains a
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>
 * <p>
 * Used by {@link BearerTokenAuthenticationFilter} to prepare an authentication attempt
 * and supported by {@link JwtAuthenticationProvider}.
 *
 * @author Josh Cummings
 */
public class BearerTokenAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;

    /**
     * Create a {@code BearerTokenAuthenticationToken} using the provided parameter(s)
     *
     * @param token - the bearer token
     */
    public BearerTokenAuthenticationToken(String token) {
        super(Collections.emptyList());
        Assert.hasText(token, "token cannot be empty");
        this.token = token;
    }

    /**
     * Get the
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
     * Token</a>
     *
     * @return the token that proves the caller's authority to perform the
     * {@link javax.servlet.http.HttpServletRequest}
     */
    public String getToken() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return getToken();
    }

    @Override
    public Object getPrincipal() {
        return getToken();
    }

}
