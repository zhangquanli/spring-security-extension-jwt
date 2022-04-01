package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.config.ProviderSettings;
import com.github.zhangquanli.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.List;

/**
 * Configurer for OAuth 2.0 Client Authentication.
 *
 * @author Joe Grandja
 * @see OAuth2ClientAuthenticationFilter
 */
public final class OAuth2ClientAuthenticationConfigurer extends AbstractOAuth2Configurer {
    private RequestMatcher requestMatcher;
    private AuthenticationConverter authenticationConverter;
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();
    private AuthenticationSuccessHandler authenticationSuccessHandler;
    private AuthenticationFailureHandler errorResponseHandler;

    @Override
    <B extends HttpSecurityBuilder<B>> void init(B builder) {
        ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
        this.requestMatcher = new OrRequestMatcher(
                new AntPathRequestMatcher(providerSettings.getTokenEndpoint(),
                        HttpMethod.POST.name()),
                new AntPathRequestMatcher(providerSettings.getTokenIntrospectionEndpoint(),
                        HttpMethod.POST.name()),
                new AntPathRequestMatcher(providerSettings.getTokenRevocationEndpoint(),
                        HttpMethod.POST.name()));

        List<AuthenticationProvider> authenticationProviders =
                !this.authenticationProviders.isEmpty() ?
                        this.authenticationProviders :
                        createDefaultAuthenticationProviders(builder);
        authenticationProviders.forEach(builder::authenticationProvider);
    }

    @Override
    <B extends HttpSecurityBuilder<B>> void configure(B builder) {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        OAuth2ClientAuthenticationFilter clientAuthenticationFilter = new OAuth2ClientAuthenticationFilter(
                authenticationManager, requestMatcher);
        if (authenticationConverter != null) {
            clientAuthenticationFilter.setAuthenticationConverter(authenticationConverter);
        }
        if (authenticationSuccessHandler != null) {
            clientAuthenticationFilter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        }
        if (errorResponseHandler != null) {
            clientAuthenticationFilter.setAuthenticationFailureHandler(errorResponseHandler);
        }
        builder.addFilterBefore(clientAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Override
    RequestMatcher getRequestMatcher() {
        return requestMatcher;
    }

    /**
     * Sets the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
     * to an instance of {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
     *
     * @param authenticationConverter the {@link AuthenticationConverter} used when attempting to extract client credentials from {@link HttpServletRequest}
     * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
     */
    public OAuth2ClientAuthenticationConfigurer authenticationConverter(AuthenticationConverter authenticationConverter) {
        this.authenticationConverter = authenticationConverter;
        return this;
    }

    /**
     * Adds an {@link AuthenticationProvider} used for authenticating an {@link OAuth2ClientAuthenticationToken}.
     *
     * @param authenticationProvider an {@link AuthenticationProvider} used for authenticating an {@link OAuth2ClientAuthenticationToken}
     * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
     */
    public OAuth2ClientAuthenticationConfigurer authenticationProvider(AuthenticationProvider authenticationProvider) {
        Assert.notNull(authenticationProvider, "authenticationProvider cannot be null");
        this.authenticationProviders.add(authenticationProvider);
        return this;
    }

    /**
     * Sets the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
     * and associating the {@link OAuth2ClientAuthenticationToken} to the {@link SecurityContext}.
     *
     * @param authenticationSuccessHandler the {@link AuthenticationSuccessHandler} used for handling a successful client authentication
     * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
     */
    public OAuth2ClientAuthenticationConfigurer authenticationSuccessHandler(AuthenticationSuccessHandler authenticationSuccessHandler) {
        this.authenticationSuccessHandler = authenticationSuccessHandler;
        return this;
    }

    /**
     * Sets the {@link AuthenticationFailureHandler} used for handling a failed client authentication
     * and returning the {@link OAuth2Error Error Response}.
     *
     * @param errorResponseHandler the {@link AuthenticationFailureHandler} used for handling a failed client authentication
     * @return the {@link OAuth2ClientAuthenticationConfigurer} for further configuration
     */
    public OAuth2ClientAuthenticationConfigurer errorResponseHandler(AuthenticationFailureHandler errorResponseHandler) {
        this.errorResponseHandler = errorResponseHandler;
        return this;
    }

    private <B extends HttpSecurityBuilder<B>> List<AuthenticationProvider> createDefaultAuthenticationProviders(B builder) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
                new OAuth2ClientAuthenticationProvider(OAuth2ConfigurerUtils.getRegisteredClientRepository(builder));
        PasswordEncoder passwordEncoder = OAuth2ConfigurerUtils.getOptionalBean(builder, PasswordEncoder.class);
        if (passwordEncoder != null) {
            clientAuthenticationProvider.setPasswordEncoder(passwordEncoder);
        }
        authenticationProviders.add(clientAuthenticationProvider);

        return authenticationProviders;
    }
}
