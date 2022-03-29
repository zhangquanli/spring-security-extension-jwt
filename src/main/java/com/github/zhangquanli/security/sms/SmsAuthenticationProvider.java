//package com.github.zhangquanli.security.sms;
//
//import com.github.zhangquanli.security.AbstractUserDetailsAuthenticationProvider;
//import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
//import org.apache.commons.logging.Log;
//import org.apache.commons.logging.LogFactory;
//import org.springframework.beans.factory.InitializingBean;
//import org.springframework.security.authentication.BadCredentialsException;
//import org.springframework.security.authentication.InternalAuthenticationServiceException;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.core.AuthenticationException;
//import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
//import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsChecker;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.util.Assert;
//
//public class SmsAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider implements InitializingBean {
//    private final Log logger = LogFactory.getLog(getClass());
//
//    private UserDetailsService userDetailsService;
//    private VerifiedCodeRepository verifiedCodeRepository;
//    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();
//
//    public SmsAuthenticationProvider() {
//        setPostAuthenticationChecks(new DefaultNullAuthenticationChecks());
//    }
//
//    @Override
//    public void afterPropertiesSet() {
//        Assert.notNull(userDetailsService, "A UserDetailsService must be set");
//        Assert.notNull(verifiedCodeRepository, "A VerifiedCodeRepository must be set");
//    }
//
//    @Override
//    public boolean supports(Class<?> authentication) {
//        return SmsAuthenticationToken.class.isAssignableFrom(authentication);
//    }
//
//    @Override
//    protected UserDetails retrieveUser(String username, AbstractJwtAuthenticationToken authentication) throws AuthenticationException {
//        UserDetails loadedUser = userDetailsService.loadUserByUsername(username);
//        try {
//            if (loadedUser == null) {
//                throw new InternalAuthenticationServiceException(
//                        "UserDetailsService returned null, which is an interface contract violation");
//            }
//            return loadedUser;
//        } catch (UsernameNotFoundException | InternalAuthenticationServiceException ex) {
//            throw ex;
//        } catch (Exception ex) {
//            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
//        }
//    }
//
//    @Override
//    protected void additionalAuthenticationChecks(UserDetails userDetails, AbstractJwtAuthenticationToken authentication)
//            throws AuthenticationException {
//        String mobile = authentication.getName();
//        if (!verifiedCodeRepository.contains(mobile)) {
//            logger.debug("Failed to authenticate since no credentials stored");
//            throw new BadCredentialsException("Bad credentials");
//        }
//        String code = authentication.getCredentials().toString();
//        if (!verifiedCodeRepository.load(mobile).equals(code)) {
//            logger.debug("Failed to authenticate since code does not match stored value");
//            throw new BadCredentialsException("Bad credentials");
//        }
//        verifiedCodeRepository.remove(mobile);
//    }
//
//    @Override
//    protected Authentication createSuccessAuthentication(Authentication authentication, UserDetails user) {
//        // Ensure we return the original credentials the user supplied,
//        // so subsequent attempts are successful even with encoded passwords.
//        // Also ensure we return the original getDetails(), so that future
//        // authentication events after cache expiry contain the details
//        SmsAuthenticationToken result = new SmsAuthenticationToken(user,
//                authentication.getCredentials(), authoritiesMapper.mapAuthorities(user.getAuthorities()));
//        result.setDetails(authentication.getDetails());
//        this.logger.debug("Authenticated user");
//        return result;
//    }
//
//    public void setUserDetailsService(UserDetailsService userDetailsService) {
//        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
//        this.userDetailsService = userDetailsService;
//    }
//
//    public void setVerifiedCodeRepository(VerifiedCodeRepository verifiedCodeRepository) {
//        Assert.notNull(verifiedCodeRepository, "verifiedCodeRepository cannot be null");
//        this.verifiedCodeRepository = verifiedCodeRepository;
//    }
//
//    public void setAuthoritiesMapper(GrantedAuthoritiesMapper authoritiesMapper) {
//        Assert.notNull(authoritiesMapper, "authoritiesMapper cannot be null");
//        this.authoritiesMapper = authoritiesMapper;
//    }
//
//    private static class DefaultNullAuthenticationChecks implements UserDetailsChecker {
//        @Override
//        public void check(UserDetails user) {
//        }
//    }
//}
