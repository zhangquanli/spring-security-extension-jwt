package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Map;

/**
 * An {@link Authentication} implementation used for the OAuth 2.0 Password Grant.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @author Daniel Garnier-Moiroux
 * @see OAuth2AuthorizationGrantAuthenticationToken
 * @see OAuth2PasswordAuthenticationProvider
 */
public class OAuth2PasswordAuthenticationToken extends OAuth2AuthorizationGrantAuthenticationToken {
    private final String username;
    private final String password;

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationToken} using the provided parameters.
     *
     * @param username the username
     * @param password the password
     */
    public OAuth2PasswordAuthenticationToken(
            String username, String password, Authentication clientPrincipal,
            @Nullable Map<String, Object> additionalParameters) {
        super(AuthorizationGrantType.PASSWORD, clientPrincipal, additionalParameters);
        Assert.hasText(username, "username cannot be empty");
        Assert.hasText(password, "password cannot be empty");
        this.username = username;
        this.password = password;
    }

    /**
     * Returns the username
     *
     * @return the username
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the password
     *
     * @return the password
     */
    public String getPassword() {
        return password;
    }
}
