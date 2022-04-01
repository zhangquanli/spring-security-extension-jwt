package com.github.zhangquanli.security.oauth2.server.authorization.web;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import com.github.zhangquanli.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import com.github.zhangquanli.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

/**
 * A {@code Filter} that processes an authentication request for an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @see AuthenticationManager
 * @see OAuth2ClientAuthenticationProvider
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-2.3" target="_blank">
 * Section 2.3 Client Authentication</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749#section-3.2.1" target="_blank">
 * Section 3.2.1 Token Endpoint Client Authentication</a>
 */
public class OAuth2ClientAuthenticationFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher requestMatcher;
    private final HttpMessageConverter<OAuth2Error> errorHttpMessageConverter =
            new OAuth2ErrorHttpMessageConverter();
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
            new WebAuthenticationDetailsSource();

    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler = this::onAuthenticationSuccess;
    private AuthenticationFailureHandler authenticationFailureHandler = this::onAuthenticationFailure;

    public OAuth2ClientAuthenticationFilter(AuthenticationManager authenticationManager, RequestMatcher requestMatcher) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(requestMatcher, "requestMatcher cannot be null");
        this.authenticationManager = authenticationManager;
        this.requestMatcher = requestMatcher;
        this.authenticationConverter = new DelegatingAuthenticationConverter(
                Arrays.asList(
                        new ClientSecretBasicAuthenticationConverter(),
                        new ClientSecretPostAuthenticationConverter()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Authentication authenticationRequest = authenticationConverter.convert(request);
            if (authenticationRequest instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authenticationRequest).setDetails(
                        authenticationDetailsSource.buildDetails(request));
            }
            if (authenticationRequest != null) {
                Authentication authenticateResult = authenticationManager.authenticate(authenticationRequest);
                authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticateResult);
            }
            filterChain.doFilter(request, response);
        } catch (OAuth2AuthenticationException ex) {
            authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        }
    }

    /**
     * Sets the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
     * to an instance of {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
     *
     * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
     */
    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
     * and associating the {@link OAuth2ClientAuthenticationToken} to the {@link SecurityContext}.
     *
     * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} used for handling a failed client authentication
     * and returning the {@link OAuth2Error Error Response}.
     *
     * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling a failed client authentication
     */
    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    private void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);
        SecurityContextHolder.setContext(securityContext);
    }

    private void onAuthenticationFailure(
            HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        SecurityContextHolder.clearContext();

        // TODO
        // The authorization server MAY return an HTTP 401 (Unauthorized) status code
        // to indicate which HTTP authentication schemes are supported.
        // If the client attempted to authenticate via the "Authorization" request header field,
        // the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and
        // include the "WWW-Authenticate" response header field
        // matching the authentication scheme used by the client.

        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        if (OAuth2ErrorCodes.INVALID_CLIENT.equals(error.getErrorCode())) {
            httpResponse.setStatusCode(HttpStatus.UNAUTHORIZED);
        } else {
            httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
        }
        // We don't want to reveal too much information to the caller so just return the error code
        OAuth2Error errorResponse = new OAuth2Error(error.getErrorCode());
        errorHttpMessageConverter.write(errorResponse, null, httpResponse);
    }
}
