package com.github.zhangquanli.security.password;

import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * An {@link org.springframework.security.core.Authentication} implementation that is
 * designed for password verification of username and password.
 * <p>
 * The <code>principal</code> and <code>credentials</code> should be set with an
 * <code>Object</code> that provides the respective property via its
 * <code>Object.toString()</code>. The simple such <code>Object</code> to use is
 * <code>String</code>.
 */
public class PasswordAuthenticationToken extends AbstractJwtAuthenticationToken {
    private final Object principal;
    private Object credentials;

    /**
     * This constructor can be safely used by any code that wishes to create a
     * <code>SmsAuthenticationToken</code>, as the {@link #isAuthenticated()}
     * will return <code>false</code>
     *
     * @param principal   username or {@link UserDetails}
     * @param credentials password
     */
    public PasswordAuthenticationToken(Object principal, Object credentials) {
        super(null);
        this.principal = principal;
        this.credentials = credentials;
        setAuthenticated(false);
    }

    /**
     * The constructor should only be used by <code>AuthenticationManager</code> or
     * <code>AuthenticationProvider</code> implementation that are satisfied with
     * producing a trusted authentication token.
     *
     * @param principal   username or {@link UserDetails}
     * @param credentials password
     * @param authorities authorities
     */
    public PasswordAuthenticationToken(
            Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.principal = principal;
        this.credentials = credentials;
        super.setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        Assert.isTrue(!isAuthenticated,
                "Cannot set this token to trusted -" +
                        " use constructor which takes a GrantedAuthority list instead");
        super.setAuthenticated(false);
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
        this.credentials = null;
    }
}
