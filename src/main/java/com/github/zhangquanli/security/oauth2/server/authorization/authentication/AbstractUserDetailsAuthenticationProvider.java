package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

abstract class AbstractUserDetailsAuthenticationProvider implements AuthenticationProvider {
    protected final Log logger = LogFactory.getLog(getClass());

    private boolean hideUserNotFoundExceptions = true;
    private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
    private UserDetailsChecker postAuthenticationChecks = new DefaultPostAuthenticationChecks();

    @Override
    public abstract boolean supports(Class<?> authentication);

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(AbstractJwtAuthenticationToken.class, authentication,
                "Only AbstractJwtAuthenticationToken is supported");
        String username = authentication.getName();
        UserDetails user;
        try {
            user = retrieveUser(username, (AbstractJwtAuthenticationToken) authentication);
            if (user == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
        } catch (UsernameNotFoundException ex) {
            logger.debug("Failed to find user '" + username + "'");
            if (!hideUserNotFoundExceptions) {
                throw ex;
            }
            throw new BadCredentialsException("Bad credentials");
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }

        preAuthenticationChecks.check(user);
        additionalAuthenticationChecks(user, (AbstractJwtAuthenticationToken) authentication);
        postAuthenticationChecks.check(user);
        return createSuccessAuthentication(authentication, user);
    }

    /**
     * Allows subclasses to actually retrieve the <code>UserDetails</code> from an
     * implementation-specific location, with the option of throwing an
     * <code>AuthenticationException</code> immediately if the presented credentials are
     * incorrect (this is especially useful if it is necessary to bind to a resource as
     * the user in order to obtain or generate a <code>UserDetails</code>).
     * <p>
     * Subclasses are not required to perform any caching, as the
     * <code>AbstractUserDetailsAuthenticationProvider</code> will by default cache the
     * <code>UserDetails</code>. The caching of <code>UserDetails</code> does present
     * additional complexity as this means subsequent requests that rely on the cache will
     * need to still have their credentials validated, even if the correctness of
     * credentials was assured by subclasses adopting a binding-based strategy in this
     * method. Accordingly it is important that subclasses either disable caching (if they
     * want to ensure that this method is the only method that is capable of
     * authenticating a request, as no <code>UserDetails</code> will ever be cached) or
     * ensure subclasses implement
     * {@link #additionalAuthenticationChecks(UserDetails, AbstractJwtAuthenticationToken)}
     * to compare the credentials of a cached <code>UserDetails</code> with subsequent
     * authentication requests.
     * </p>
     * <p>
     * Most of the time subclasses will not perform credentials inspection in this method,
     * instead performing it in
     * {@link #additionalAuthenticationChecks(UserDetails, AbstractJwtAuthenticationToken)}
     * so that code related to credentials validation need not be duplicated across two
     * methods.
     * </p>
     *
     * @param username       The username to retrieve
     * @param authentication The authentication request, which subclasses <em>may</em>
     *                       need to perform a binding-based retrieval of the <code>UserDetails</code>
     * @return the user information (never <code>null</code> - instead an exception should
     * the thrown)
     * @throws AuthenticationException if the credentials could not be validated
     *                                 (generally a <code>BadCredentialsException</code>, an
     *                                 <code>AuthenticationServiceException</code> or
     *                                 <code>UsernameNotFoundException</code>)
     */
    protected abstract UserDetails retrieveUser(String username, AbstractJwtAuthenticationToken authentication)
            throws AuthenticationException;

    /**
     * Allows subclasses to perform any additional checks of a returned (or cached)
     * <code>UserDetails</code> for a given authentication request. Generally a subclass
     * will at least compare the {@link Authentication#getCredentials()} with a
     * {@link UserDetails#getPassword()}. If custom logic is needed to compare additional
     * properties of <code>UserDetails</code> and/or
     * <code>UsernamePasswordAuthenticationToken</code>, these should also appear in this
     * method.
     *
     * @param userDetails    as retrieved from the
     *                       {@link #retrieveUser(String, AbstractJwtAuthenticationToken)} or
     *                       <code>UserCache</code>
     * @param authentication the current request that needs to be authenticated
     * @throws AuthenticationException if the credentials could
     *                                 not be validated (generally a <code>BadCredentialsException</code>, an
     *                                 <code>AuthenticationServiceException</code>)
     */
    protected abstract void additionalAuthenticationChecks(
            UserDetails userDetails, AbstractJwtAuthenticationToken authentication) throws AuthenticationException;

    /**
     * Creates a successful {@link Authentication} object.
     * <p>
     * Protected so subclasses can override.
     * </p>
     * <p>
     * Subclasses will usually store the original credentials the user supplied (not
     * salted or encoded passwords) in the returned <code>Authentication</code> object.
     * </p>
     *
     * @param authentication that was presented to the provider for validation
     * @param user           that was loaded by the implementation
     * @return the successful authentication token
     */
    protected abstract Authentication createSuccessAuthentication(
            Authentication authentication, UserDetails user) throws AuthenticationException;

    public void setHideUserNotFoundExceptions(boolean hideUserNotFoundExceptions) {
        this.hideUserNotFoundExceptions = hideUserNotFoundExceptions;
    }

    public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
        this.preAuthenticationChecks = preAuthenticationChecks;
    }

    public void setPostAuthenticationChecks(UserDetailsChecker postAuthenticationChecks) {
        this.postAuthenticationChecks = postAuthenticationChecks;
    }

    private class DefaultPreAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isAccountNonLocked()) {
                logger.debug("Failed to authenticate since user account is locked");
                throw new LockedException("User account is locked");
            }
            if (!user.isEnabled()) {
                logger.debug("Failed to authenticate since user account is disabled");
                throw new DisabledException("User account is disabled");
            }
            if (!user.isAccountNonExpired()) {
                logger.debug("Failed to authenticate since user account has expired");
                throw new AccountExpiredException("User account has expired");
            }
        }

    }

    private class DefaultPostAuthenticationChecks implements UserDetailsChecker {
        @Override
        public void check(UserDetails user) {
            if (!user.isCredentialsNonExpired()) {
                logger.debug("Failed to authenticate since user account credentials have expired");
                throw new CredentialsExpiredException("User credentials have expired");
            }
        }
    }
}
