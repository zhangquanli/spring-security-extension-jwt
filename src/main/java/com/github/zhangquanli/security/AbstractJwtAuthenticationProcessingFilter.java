package com.github.zhangquanli.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractJwtAuthenticationProcessingFilter extends GenericFilterBean {
    private AuthenticationManager authenticationManager;
    private RequestMatcher requiresAuthenticationRequestMatcher;
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
            new WebAuthenticationDetailsSource();
    private Converter<AbstractJwtAuthenticationToken, JwtClaimsSet> jwtClaimsSetConverter;
    private Duration expiresIn;
    private JwtEncoder jwtEncoder;
    private AuthenticationSuccessHandler successHandler;
    private AuthenticationFailureHandler failureHandler;

    protected AbstractJwtAuthenticationProcessingFilter(
            RequestMatcher requiresAuthenticationRequestMatcher) {
        this(requiresAuthenticationRequestMatcher, null);
    }

    protected AbstractJwtAuthenticationProcessingFilter(
            RequestMatcher requiresAuthenticationRequestMatcher, AuthenticationManager authenticationManager) {
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
        this.authenticationManager = authenticationManager;
    }

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(authenticationManager, "authenticationManager must be specified");
        Assert.notNull(successHandler, "successHandler must be specified");
        Assert.notNull(failureHandler, "failureHandler must be specified");
        Assert.notNull(expiresIn, "expiresIn must be specified");
        Assert.notNull(jwtEncoder, "jwtEncoder must be specified");
    }

    /**
     * Invokes the {@link #requiresAuthentication(HttpServletRequest, HttpServletResponse)
     * requiresAuthentication} method to determine whether the request is
     * for authentication and should be handled by this filter. If it is an authentication
     * request, the {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)
     * attemptAuthentication} will be invoked to perform the authentication. There are
     * then three possible outcomes:
     * <ol>
     * <li>An <tt>Authentication</tt> object is returned. The
     * {@link #successfulAuthentication(HttpServletRequest, HttpServletResponse, FilterChain, Authentication)
     * successfulAuthentication} method will be invoked</li>
     * <li>An <tt>AuthenticationException</tt> occurs during authentication. The
     * {@link #unsuccessfulAuthentication(HttpServletRequest, HttpServletResponse, AuthenticationException)
     * unsuccessfulAuthentication} method will be invoked</li>
     * <li>Null is returned, indicating that the authentication process is incomplete. The
     * method will then return immediately, assuming that the subclass has done any
     * necessary work (suck as redirects) to continue the authentication process. The
     * assumption is that a later request will be received by this method where the
     * returned <tt>Authentication</tt> object is not null.</li>
     * </ol>
     *
     * @param request  the {@link ServletRequest}
     * @param response the {@link ServletResponse}
     * @param chain    the {@link FilterChain}
     * @throws IOException      if process fails
     * @throws ServletException if process fails
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        doFilter((HttpServletRequest) request, (HttpServletResponse) response, chain);
    }

    private void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!requiresAuthentication(request, response)) {
            chain.doFilter(request, response);
            return;
        }
        try {
            Authentication authenticationResult = attemptAuthentication(request, response);
            if (authenticationResult == null) {
                // return immediately as subclass has indicated that it hasn't completed
                return;
            }
            successfulAuthentication(request, response, chain, authenticationResult);
        } catch (InternalAuthenticationServiceException failed) {
            logger.error("An internal error occurred while trying to authenticate the user.", failed);
            unsuccessfulAuthentication(request, response, failed);
        } catch (AuthenticationException ex) {
            // Authentication failed
            unsuccessfulAuthentication(request, response, ex);
        }
    }

    /**
     * Indicates whether this filter should attempt to process a login request for the
     * current invocation.
     *
     * @param request  the {@link HttpServletRequest}
     * @param response the {@link HttpServletResponse}
     * @return whether this filer should invoke
     */
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        if (requiresAuthenticationRequestMatcher.matches(request)) {
            return true;
        }
        logger.trace(LogMessage.format("Did not match request to %s", requiresAuthenticationRequestMatcher));
        return false;
    }

    /**
     * Performs actual authentication.
     * <p>
     * The implementation should do one of the following:
     * <ol>
     * <li>Return a populated authentication token for the authenticated user, indicating
     * successful authentication</li>
     * <li>Return null, indicating that the authentication process is still in progress.
     * Before returning, the implementation should perform any additional work required to
     * complete the process.</li>
     * <li>Throw an <tt>AuthenticationException</tt> if the authentication processes
     * fails</li>
     * </ol>
     *
     * @param request  the {@link HttpServletRequest}
     * @param response the {@link HttpServletResponse}
     * @return the authentication user token, or null if authentication is incomplete.
     * @throws AuthenticationException if authentication fails
     * @throws IOException             if authentication fails
     * @throws ServletException        if authentication fails
     */
    protected abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;

    /**
     * Default behavior for successful authentication.
     * <ol>
     * <li>Sets the successful <tt>Authentication</tt> object on the {@link SecurityContextHolder}</li>
     * <li>Delegates additional behavior to the {@link AuthenticationSuccessHandler}</li>
     * </ol>
     *
     * @param request    the {@link HttpServletRequest}
     * @param response   the {@link HttpServletResponse}
     * @param chain      the {@link FilterChain}
     * @param authResult the authentication returned from the
     *                   {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)}
     * @throws IOException      if process fails
     * @throws ServletException if process fails
     */
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        AbstractJwtAuthenticationToken jwtAuthResult = (AbstractJwtAuthenticationToken) authResult;
        JwsHeader headers = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtClaimsSet claims = jwtClaimsSet(jwtAuthResult);
        JwtEncoderParameters parameters = JwtEncoderParameters.from(headers, claims);
        Jwt jwt = jwtEncoder.encode(parameters);
        jwtAuthResult.setJwt(jwt);

        SecurityContextHolder.getContext().setAuthentication(jwtAuthResult);
        logger.debug(LogMessage.format("Set SecurityContextHolder to %s", jwtAuthResult));
        successHandler.onAuthenticationSuccess(request, response, jwtAuthResult);
    }

    private JwtClaimsSet jwtClaimsSet(AbstractJwtAuthenticationToken authResult) {
        String subject = authResult.getName();
        List<String> audience = Collections.singletonList(
                ((WebAuthenticationDetails) authResult.getDetails()).getRemoteAddress());
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(expiresIn);
        Set<String> scope = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        if (jwtClaimsSetConverter != null &&
                jwtClaimsSetConverter.convert(authResult) != null) {
            return JwtClaimsSet.from(jwtClaimsSetConverter.convert(authResult))
                    .subject(subject)
                    .audience(audience)
                    .issuedAt(issuedAt)
                    .expiresAt(expiresAt)
                    .notBefore(issuedAt)
                    .claim("scope", scope)
                    .build();
        }
        return JwtClaimsSet.builder()
                .subject(subject)
                .audience(audience)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .claim("scope", scope)
                .build();
    }

    /**
     * Default behavior for unsuccessful authentication.
     * <ol>
     * <li>Clears the {@link SecurityContextHolder}</li>
     * <li>Delegates additional behavior to the {@link AuthenticationFailureHandler}</li>
     * </ol>
     *
     * @param request  the {@link HttpServletRequest}
     * @param response the {@link HttpServletResponse}
     * @param failed   the exception caught from the
     *                 {@link #attemptAuthentication(HttpServletRequest, HttpServletResponse)}
     * @throws IOException      if process fails
     * @throws ServletException if process fails
     */
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        logger.trace("Failed to process authentication request", failed);
        logger.trace("Cleared SecurityContextHolder");
        logger.trace("Handing authentication failure");
        failureHandler.onAuthenticationFailure(request, response, failed);
    }

    public void setAuthenticationManager(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManager = authenticationManager;
    }

    public void setRequiresAuthenticationRequestMatcher(
            RequestMatcher requiresAuthenticationRequestMatcher) {
        Assert.notNull(requiresAuthenticationRequestMatcher, "requiresAuthenticationRequestMatcher cannot be null");
        this.requiresAuthenticationRequestMatcher = requiresAuthenticationRequestMatcher;
    }

    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    public void setJwtClaimsSetConverter(
            Converter<AbstractJwtAuthenticationToken, JwtClaimsSet> jwtClaimsSetConverter) {
        Assert.notNull(authenticationDetailsSource, "jwtClaimsSetConverter cannot be null");
        this.jwtClaimsSetConverter = jwtClaimsSetConverter;
    }

    /**
     * Sets the expiresIn which will be used to expiration of an jwt.
     *
     * @param expiresIn the {@link Duration}
     */
    public void setExpiresIn(Duration expiresIn) {
        Assert.notNull(expiresIn, "expiresIn cannot be null");
        this.expiresIn = expiresIn;
    }

    /**
     * Sets the jwtEncoder which will be used to generate an jwt.
     *
     * @param jwtEncoder the {@link JwtEncoder}
     */
    public void setJwtEncoder(JwtEncoder jwtEncoder) {
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.jwtEncoder = jwtEncoder;
    }

    public void setSuccessHandler(AuthenticationSuccessHandler successHandler) {
        Assert.notNull(successHandler, "successHandler cannot be null");
        this.successHandler = successHandler;
    }

    public void setFailureHandler(AuthenticationFailureHandler failureHandler) {
        Assert.notNull(failureHandler, "failureHandler cannot be null");
        this.failureHandler = failureHandler;
    }

    protected final AuthenticationManager getAuthenticationManager() {
        return authenticationManager;
    }

    protected final AuthenticationDetailsSource<HttpServletRequest, ?> getAuthenticationDetailsSource() {
        return authenticationDetailsSource;
    }
}
