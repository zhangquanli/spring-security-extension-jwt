package com.github.zhangquanli.security.sms;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation that retrieves user details from a
 * {@link UserDetailsService}.
 */
public class SmsAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    private final Log logger = LogFactory.getLog(getClass());
    private UserDetailsService userDetailsService;
    private VerifiedCodeRepository verifiedCodeRepository;
    private UserDetailsChecker preAuthenticationChecks = new DefaultPreAuthenticationChecks();
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    public final void afterPropertiesSet() {
        Assert.notNull(userDetailsService, "A UserDetailsService must be set");
        Assert.notNull(verifiedCodeRepository, "A VerifiedCodeRepository must be set");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Assert.isInstanceOf(SmsAuthenticationToken.class, authentication,
                "Only SmsAuthenticationToken is supported");

        String mobile = determineMobile(authentication);
        UserDetails user;
        try {
            user = userDetailsService.loadUserByUsername(mobile);
            if (user == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailService returned null, which is an interface contract violation");
            }
        } catch (UsernameNotFoundException ex) {
            logger.debug("Failed to fin user '" + mobile + "'");
            throw new BadCredentialsException("Bad credentials");
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception e) {
            throw new InternalAuthenticationServiceException(e.getMessage(), e);
        }

        preAuthenticationChecks.check(user);
        additionalAuthenticationChecks((SmsAuthenticationToken) authentication);
        return createSuccessAuthentication(user, authentication);
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setVerifiedCodeRepository(VerifiedCodeRepository verifiedCodeRepository) {
        this.verifiedCodeRepository = verifiedCodeRepository;
    }

    public void setPreAuthenticationChecks(UserDetailsChecker preAuthenticationChecks) {
        this.preAuthenticationChecks = preAuthenticationChecks;
    }

    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
        this.authoritiesMapper = authoritiesMapper;
    }

    private Authentication createSuccessAuthentication(UserDetails user, Authentication authentication) {
        // Ensure we return the original credentials the user supplied,
        // so subsequent attempts are successful even with encoded password.
        // Also ensure we return the original getDetails(), so that future
        // authentication events after cache expiry contain the details
        SmsAuthenticationToken result = new SmsAuthenticationToken(user, authentication.getCredentials(),
                authoritiesMapper.mapAuthorities(user.getAuthorities()));
        result.setDetails(authentication.getDetails());
        logger.debug("Authenticated user");
        return result;
    }

    private void additionalAuthenticationChecks(SmsAuthenticationToken authentication) throws AuthenticationException {
        String mobile = determineMobile(authentication);
        if (!verifiedCodeRepository.contains(mobile)) {
            logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException("Bad credentials");
        }
        String code = authentication.getCredentials().toString();
        if (!verifiedCodeRepository.load(mobile).equals(code)) {
            logger.debug("Failed to authenticate since code does not match stored value");
            throw new BadCredentialsException("Bad credentials");
        }
        verifiedCodeRepository.remove(mobile);
    }

    private String determineMobile(Authentication authentication) {
        return authentication.getPrincipal() == null ? "NONE_PROVIDED" : authentication.getName();
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SmsAuthenticationToken.class.isAssignableFrom(authentication);
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
}
