package com.github.zhangquanli.security.oauth2.server.authorization.web;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.authorization.web.authentication.DelegatingAuthenticationConverter;
import com.github.zhangquanli.security.oauth2.server.authorization.web.authentication.OAuth2PasswordAuthenticationConverter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.http.converter.OAuth2ErrorHttpMessageConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;

/**
 * A {@code Filter} for the OAuth 2.0 Token endpoint,
 * which handles the processing of an OAuth 2.0 Authorization Grant.
 *
 * <p>
 * It converts the OAuth 2.0 Authorization Grant requests to an {@link Authentication},
 * which is then authenticated by the {@link AuthenticationManager}.
 * If the authentication succeeds, the {@link AuthenticationManager} returns an
 * {@link OAuth2AccessTokenAuthenticationToken}, which is returned in the OAuth 2.0 Access Token response.
 * In case of any error, an {@link OAuth2Error} is returned in the OAuth 2.0 Error response.
 *
 * <p>
 * By default, this {@code Filter} responds to authorization grant requests
 * at the {@code URI} {@code /oauth2/token} and {@code HttpMethod} {@code POST}.
 *
 * <p>
 * The default endpoint {@code URI} {@code /oauth2/token} may be overridden
 * via the constructor {@link #OAuth2TokenEndpointFilter(AuthenticationManager, String)}.
 *
 * @author Joe Grandja
 * @author Madhu Bhat
 * @author Daniel Garnier-Moiroux
 * @see AuthenticationManager
 * @see OAuth2PasswordAuthenticationProvider
 * @see OAuth2RefreshTokenAuthenticationProvider
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-3.2" target="_blank">
 * Section 3.2 Token Endpoint</a>
 */
public class OAuth2TokenEndpointFilter extends OncePerRequestFilter {
    /**
     * The default endpoint {@code URI} for access token requests.
     */
    private static final String DEFAULT_TOKEN_ENDPOINT_URI = "/oauth2/token";

    private static final String DEFAULT_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";
    private final AuthenticationManager authenticationManager;
    private final RequestMatcher tokenEndpointMatcher;
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
    private final HttpMessageConverter<OAuth2Error> errorHttpResponseConverter =
            new OAuth2ErrorHttpMessageConverter();

    private AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource =
            new WebAuthenticationDetailsSource();
    private AuthenticationConverter authenticationConverter;
    private AuthenticationSuccessHandler authenticationSuccessHandler = this::sendAccessTokenResponse;
    private AuthenticationFailureHandler authenticationFailureHandler = this::sendErrorResponse;

    /**
     * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     */
    public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager) {
        this(authenticationManager, DEFAULT_TOKEN_ENDPOINT_URI);
    }

    /**
     * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     * @param tokenEndpointUri      the endpoint {@code URI} for access token requests
     */
    public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager, String tokenEndpointUri) {
        this(authenticationManager, new AntPathRequestMatcher(tokenEndpointUri, HttpMethod.POST.name()));
    }

    /**
     * Constructs an {@code OAuth2TokenEndpointFilter} using the provided parameters.
     *
     * @param authenticationManager the authentication manager
     * @param tokenEndpointMatcher  the endpoint {@code URI} for access token requests
     */
    public OAuth2TokenEndpointFilter(AuthenticationManager authenticationManager, RequestMatcher tokenEndpointMatcher) {
        Assert.notNull(authenticationManager, "authenticationManager cannot be null");
        Assert.notNull(tokenEndpointMatcher, "tokenEndpointMatcher cannot be empty");
        this.authenticationManager = authenticationManager;
        this.tokenEndpointMatcher = tokenEndpointMatcher;
        this.authenticationConverter = new DelegatingAuthenticationConverter(
                Collections.singletonList(
                        new OAuth2PasswordAuthenticationConverter()));
    }


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!tokenEndpointMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String[] grantTypes = request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE);
            if (grantTypes == null || grantTypes.length != 1) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST,
                        "OAuth 2.0 Parameter: " + OAuth2ParameterNames.GRANT_TYPE, DEFAULT_ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            Authentication authorizationGrantAuthentication = authenticationConverter.convert(request);
            if (authorizationGrantAuthentication == null) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.UNSUPPORTED_GRANT_TYPE,
                        "OAuth 2.0 Parameter: " + OAuth2ParameterNames.GRANT_TYPE, DEFAULT_ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }
            if (authorizationGrantAuthentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authorizationGrantAuthentication)
                        .setDetails(authenticationDetailsSource.buildDetails(request));
            }

            OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
                    (OAuth2AccessTokenAuthenticationToken) authenticationManager.authenticate(authorizationGrantAuthentication);
            authenticationSuccessHandler.onAuthenticationSuccess(request, response, accessTokenAuthentication);
        } catch (OAuth2AuthenticationException ex) {
            SecurityContextHolder.clearContext();
            authenticationFailureHandler.onAuthenticationFailure(request, response, ex);
        }
    }

    /**
     * Sets the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}.
     *
     * @param authenticationDetailsSource the {@link AuthenticationDetailsSource} used for building an authentication details instance from {@link HttpServletRequest}
     */
    public void setAuthenticationDetailsSource(AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        Assert.notNull(authenticationDetailsSource, "authenticationDetailsSource cannot be null");
        this.authenticationDetailsSource = authenticationDetailsSource;
    }

    /**
     * Sets the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
     * to an instance of {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the authorization grant.
     *
     * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
     */
    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
     * and returning the {@link OAuth2AccessTokenResponse Access Token Response}.
     *
     * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
     */
    public void setAuthenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        Assert.notNull(authenticationSuccessHandler, "authenticationSuccessHandler cannot be null");
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
     * and returning the {@link OAuth2Error Error Response}.
     *
     * @param authenticationFailureHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
     */
    public void setAuthenticationFailureHandler(AuthenticationFailureHandler authenticationFailureHandler) {
        Assert.notNull(authenticationFailureHandler, "authenticationFailureHandler cannot be null");
        this.authenticationFailureHandler = authenticationFailureHandler;
    }

    private void sendAccessTokenResponse(
            HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException {
        OAuth2AccessTokenAuthenticationToken accessTokenAuthentication =
                (OAuth2AccessTokenAuthenticationToken) authentication;

        OAuth2AccessToken accessToken = accessTokenAuthentication.getAccessToken();
        OAuth2RefreshToken refreshToken = accessTokenAuthentication.getRefreshToken();
        Map<String, Object> additionalParameters = accessTokenAuthentication.getAdditionalParameters();

        OAuth2AccessTokenResponse.Builder builder =
                OAuth2AccessTokenResponse.withToken(accessToken.getTokenValue())
                        .tokenType(accessToken.getTokenType())
                        .scopes(accessToken.getScopes());
        if (accessToken.getIssuedAt() != null && accessToken.getExpiresAt() != null) {
            builder.expiresIn(ChronoUnit.SECONDS.between(accessToken.getIssuedAt(), accessToken.getExpiresAt()));
        }
        if (refreshToken != null) {
            builder.refreshToken(refreshToken.getTokenValue());
        }
        if (!CollectionUtils.isEmpty(additionalParameters)) {
            builder.additionalParameters(additionalParameters);
        }
        OAuth2AccessTokenResponse accessTokenResponse = builder.build();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
    }

    private void sendErrorResponse(
            HttpServletRequest request, HttpServletResponse response,
            AuthenticationException exception) throws IOException {
        OAuth2Error error = ((OAuth2AuthenticationException) exception).getError();
        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        httpResponse.setStatusCode(HttpStatus.BAD_REQUEST);
        errorHttpResponseConverter.write(error, null, httpResponse);
    }
}
