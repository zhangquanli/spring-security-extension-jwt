package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.oauth2.server.authorization.OAuth2AuthorizationService;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2AuthorizationGrantAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Configurer for the OAuth 2.0 Token Endpoint.
 *
 * @author Joe Grandja
 * @see OAuth2AuthorizationServerConfigurer#tokenEndpoint
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2TokenEndpointConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<OAuth2TokenEndpointConfigurer<H>, H> {
    private RequestMatcher requestMatcher;
    private AuthenticationConverter accessTokenRequestConverter;
    private final List<AuthenticationProvider> authenticationProviders = new LinkedList<>();
    private AuthenticationSuccessHandler accessTokenResponseHandler;
    private AuthenticationFailureHandler errorResponseHandler;

    /**
     * Sets the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
     * to an instance of {@link OAuth2AuthorizationGrantAuthenticationToken} used for authenticating the authorization grant.
     *
     * @param accessTokenRequestConverter the {@link AuthenticationConverter} used when attempting to extract an Access Token Request from {@link HttpServletRequest}
     * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
     */
    public OAuth2TokenEndpointConfigurer<H> accessTokenRequestConverter(AuthenticationConverter accessTokenRequestConverter) {
        this.accessTokenRequestConverter = accessTokenRequestConverter;
        return this;
    }

    /**
     * Adds an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2AuthorizationGrantAuthenticationToken}.
     *
     * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating a type of {@link OAuth2AuthorizationGrantAuthenticationToken}
     * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
     */
    public OAuth2TokenEndpointConfigurer<H> authenticationProvider(AuthenticationProvider authenticationProvider) {
        Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
     * and returning the {@link OAuth2AccessTokenResponse Access Token Response}.
     *
     * @param accessTokenResponseHandler the {@link AuthenticationSuccessHandler} used for handling an {@link OAuth2AccessTokenAuthenticationToken}
     * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
     */
    public OAuth2TokenEndpointConfigurer<H> accessTokenResponseHandler(AuthenticationSuccessHandler accessTokenResponseHandler) {
        this.accessTokenResponseHandler = accessTokenResponseHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
     * and returning the {@link OAuth2Error Error Response}.
     *
     * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling an {@link OAuth2AuthenticationException}
     * @return the {@link OAuth2TokenEndpointConfigurer} for further configuration
     */
    public OAuth2TokenEndpointConfigurer<H> errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
        this.errorResponseHandler = errorResponseHandler;
        return this;
    }

    @Override
    public void init(H http) {
        this.requestMatcher = new AntPathRequestMatcher("/oauth2/token", HttpMethod.POST.name());

        List<AuthenticationProvider> authenticationProviders = !this.authenticationProviders.isEmpty() ?
                this.authenticationProviders : createDefaultAuthenticationProviders(http);
        authenticationProviders.forEach(http::authenticationProvider);
    }

    @Override
    public void configure(H http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

        OAuth2TokenEndpointFilter tokenEndpointFilter =
                new OAuth2TokenEndpointFilter(authenticationManager, "/oauth2/token");
        if (accessTokenRequestConverter != null) {
            tokenEndpointFilter.setAuthenticationConverter(accessTokenRequestConverter);
        }
        if (accessTokenResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationSuccessHandler(accessTokenResponseHandler);
        }
        if (errorResponseHandler != null) {
            tokenEndpointFilter.setAuthenticationFailureHandler(errorResponseHandler);
        }
        http.addFilterBefore(tokenEndpointFilter, UsernamePasswordAuthenticationFilter.class);
    }

    private List<AuthenticationProvider> createDefaultAuthenticationProviders(H http) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        OAuth2AuthorizationService authorizationService = OAuth2ConfigurerUtils.getAuthorizationService(http);
        UserDetailsService userDetailsService = OAuth2ConfigurerUtils.getUserDetailsService(http);
        JwtEncoder jwtEncoder = OAuth2ConfigurerUtils.getJwtEncoder(http);

        OAuth2PasswordAuthenticationProvider passwordAuthenticationProvider =
                new OAuth2PasswordAuthenticationProvider(authorizationService, userDetailsService, jwtEncoder);
        authenticationProviders.add(passwordAuthenticationProvider);

        return authenticationProviders;
    }

}
