package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Base implementation of an {@link Authentication} representing an OAuth 2.0 Authorization Grant.
 *
 * @author Joe Grandja
 * @see AbstractAuthenticationToken
 * @see AuthorizationGrantType
 * @see OAuth2ClientAuthenticationToken
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.3" target="_blank">
 * Section 1.3 Authorization Grant</a>
 */
public abstract class OAuth2AuthorizationGrantAuthenticationToken extends AbstractAuthenticationToken {
    private final AuthorizationGrantType authorizationGrantType;
    private final Authentication clientPrincipal;
    private final Map<String, Object> additionalParameters;

    /**
     * Sub-class constructor.
     *
     * @param authorizationGrantType the authorization grant type
     * @param clientPrincipal        the authenticated client principal
     * @param additionalParameters   the additional parameters
     */
    protected OAuth2AuthorizationGrantAuthenticationToken(
            AuthorizationGrantType authorizationGrantType,
            Authentication clientPrincipal, @Nullable Map<String, Object> additionalParameters) {
        super(Collections.emptyList());
        Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
        Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
        this.authorizationGrantType = authorizationGrantType;
        this.clientPrincipal = clientPrincipal;
        this.additionalParameters = Collections.unmodifiableMap(
                additionalParameters != null ?
                        new HashMap<>(additionalParameters) :
                        Collections.emptyMap());
    }

    /**
     * Returns the authorization grant type.
     *
     * @return the authorization grant type
     */
    public AuthorizationGrantType getGrantType() {
        return authorizationGrantType;
    }

    @Override
    public Object getPrincipal() {
        return clientPrincipal;
    }

    @Override
    public Object getCredentials() {
        return "";
    }

    /**
     * Returns the additional parameters.
     *
     * @return the additional parameters
     */
    public Map<String, Object> getAdditionalParameters() {
        return additionalParameters;
    }
}
