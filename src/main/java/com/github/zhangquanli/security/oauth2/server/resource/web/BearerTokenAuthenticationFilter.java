package com.github.zhangquanli.security.oauth2.server.resource.web;

import com.github.zhangquanli.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Authenticates requests that contain an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
 * Token</a>
 * <p>
 * This filter should be wired with an {@link AuthenticationManager} that can authenticate
 * a {@link BearerTokenAuthenticationToken}.
 *
 * @author Josh Cummings
 * @author Vedran Pavic
 * @author Joe Grandja
 * @see <a href="https://tools.ietf.org/html/rfc6750" target="_blank">The OAuth 2.0
 * Authorization Framework: Bearer Token Usage</a>
 * @see JwtAuthenticationProvider
 */
public class BearerTokenAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
    private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
    private AuthenticationFailureHandler authenticationFailureHandler = (request, response, exception) -> {
        if (exception instanceof AuthenticationServiceException) {
            throw exception;
        }
        authenticationEntryPoint.commence(request, response, exception);
    };
    private BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();

    /**
     * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
     *
     * @param authenticationManagerResolver the {@link AuthenticationManagerResolver}
     */
    public BearerTokenAuthenticationFilter(
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
        Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
        this.authenticationManagerResolver = authenticationManagerResolver;
    }

    /**
     * Construct a {@code BearerTokenAuthenticationFilter} using the provided parameter(s)
     *
     * @param authenticationManager the {@link AuthenticationManager}
     */
    public BearerTokenAuthenticationFilter(AuthenticationManager authenticationManager) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        this.authenticationManagerResolver = (request) -> authenticationManager;
    }

    /**
     * Extract any
     * <a href="https://tools.ietf.org/html/rfc6750#section-1.2" target="_blank">Bearer
     * Token</a> from the request and attempt an authentication.
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String token;
        try {
            token = bearerTokenResolver.resolve(request);
        } catch (OAuth2AuthenticationException invalid) {
            logger.trace("Sending to authentication entry point since failed to resolve bearer token", invalid);
            authenticationEntryPoint.commence(request, response, invalid);
            return;
        }
        if (token == null) {
            logger.trace("Did not process request since did not find bearer token");
            filterChain.doFilter(request, response);
            return;
        }

        BearerTokenAuthenticationToken authenticationRequest = new BearerTokenAuthenticationToken(token);
        authenticationRequest.setDetails(authenticationDetailsSource.buildDetails(request));

        try {
            AuthenticationManager authenticationManager = authenticationManagerResolver.resolve(request);
            Authentication authenticationResult = authenticationManager.authenticate(authenticationRequest);
            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authenticationResult);
            SecurityContextHolder.setContext(context);
            if (logger.isDebugEnabled()) {
                logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authenticationResult));
            }
            filterChain.doFilter(request, response);
        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();
            logger.trace("Failed to process authentication request", failed);
            authenticationFailureHandler.onAuthenticationFailure(request, response, failed);
        }
    }

    /**
     * Set the {@link BearerTokenResolver} to use. Defaults to
     * {@link DefaultBearerTokenResolver}.
     *
     * @param bearerTokenResolver the {@code Bearer Token Resolver} to use
     */
    public void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
        this.bearerTokenResolver = bearerTokenResolver;
    }

    /**
     * Set the {@link AuthenticationEntryPoint} to use. Defaults to
     * {@link BearerTokenAuthenticationEntryPoint}.
     *
     * @param authenticationEntryPoint the {@code AuthenticationEntryPoint} to use
     */
    public void setAuthenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    /**
     * Set the {@link AuthenticationFailureHandler} to use. Default implementation invokes
     * {@link AuthenticationEntryPoint}.
     *
     * @param authenticationFailureHandler the {@code AuthenticationFailureHandler} to use
     */
    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    /**
     * Set the {@link AuthenticationDetailsSource} to use. Defaults to
     * {@link WebAuthenticationDetailsSource}.
     *
     * @param authenticationDetailsSource the {@code AuthenticationConverter} to use
     */
    public void setAuthenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

}
