package com.github.zhangquanli.security.oauth2.server.resource.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AbstractOAuth2Token;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.Map;

/**
 * Base class for {@link AbstractAuthenticationToken} implementations that expose common
 * attributes between different OAuth 2.0 Access Token Formats.
 * <p>
 * For example, a {@link Jwt} could expose its {@link Jwt#getClaims() claims} via
 * {@link #getTokenAttributes()} or an &quot;Introspected&quot; OAuth 2.0 Access Token
 * could expose the attributes of the Introspection Response via
 * {@link #getTokenAttributes()}.
 *
 * @author Joe Grandja
 * @see OAuth2AccessToken
 * @see Jwt
 * @see <a href="https://tools.ietf.org/search/rfc7662#section-2.2" target="_blank" >2.2
 * Introspection Response</a>
 */
public abstract class AbstractOAuth2TokenAuthenticationToken<T extends AbstractOAuth2Token>
        extends AbstractAuthenticationToken {

    private final Object principal;
    private final Object credentials;
    private final T token;

    protected AbstractOAuth2TokenAuthenticationToken(T token) {
        this(token, null);
    }

    protected AbstractOAuth2TokenAuthenticationToken(T token, Collection<? extends GrantedAuthority> authorities) {
        this(token, token, token, authorities);
    }

    protected AbstractOAuth2TokenAuthenticationToken(
            T token, Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        Assert.notNull(token, "token cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        this.principal = principal;
        this.credentials = credentials;
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    /**
     * Get the token bound to this {@link Authentication}
     *
     * @return the {@link AbstractOAuth2Token}
     */
    public final T getToken() {
        return token;
    }

    /**
     * Returns the attributes of the access token.
     *
     * @return a {@code Map} of the attributes in the access token.
     */
    public abstract Map<String, Object> getTokenAttributes();

}
