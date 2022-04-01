package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.oauth2.server.authorization.OAuth2AuthorizationService;
import com.github.zhangquanli.security.oauth2.server.authorization.client.RegisteredClientRepository;
import com.github.zhangquanli.security.oauth2.server.authorization.config.ProviderSettings;
import com.github.zhangquanli.security.oauth2.server.authorization.web.ProviderContextFilter;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * An {@link AbstractHttpConfigurer} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @author Gerardo Roza
 * @author Ovidiu Popa
 * @see AbstractHttpConfigurer
 * @see OAuth2ClientAuthenticationConfigurer
 * @see OAuth2TokenEndpointConfigurer
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 */
public class OAuth2AuthorizationServerConfigurer<B extends HttpSecurityBuilder<B>>
        extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<B>, B> {

    private final Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers =
            createConfigurers();

    /**
     * Sets the provider settings.
     *
     * @param providerSettings the provider settings
     * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
     */
    public OAuth2AuthorizationServerConfigurer<B> providerSettings(ProviderSettings providerSettings) {
        Assert.notNull(providerSettings, "providerSettings cannot be null");
        getBuilder().setSharedObject(ProviderSettings.class, providerSettings);
        return this;
    }

    /**
     * Configures OAuth 2.0 Client Authentication.
     *
     * @param clientAuthenticationCustomizer the {@link  Customizer} provided access to the {@link OAuth2ClientAuthenticationConfigurer}
     * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
     */
    public OAuth2AuthorizationServerConfigurer<B> clientAuthentication(
            Customizer<OAuth2ClientAuthenticationConfigurer> clientAuthenticationCustomizer) {
        clientAuthenticationCustomizer.customize(getConfigurer(OAuth2ClientAuthenticationConfigurer.class));
        return this;
    }

    /**
     * Configures OAuth 2.0 Token Endpoint.
     *
     * @param tokenEndpointCustomizer the {@link  Customizer} provided access to the {@link OAuth2TokenEndpointConfigurer}
     * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
     */
    public OAuth2AuthorizationServerConfigurer<B> tokenEndpoint(
            Customizer<OAuth2TokenEndpointConfigurer> tokenEndpointCustomizer) {
        tokenEndpointCustomizer.customize(getConfigurer(OAuth2TokenEndpointConfigurer.class));
        return this;
    }

    @Override
    public void init(B builder) {
        ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
        validateProviderSettings(providerSettings);

        configurers.values().forEach(configurer -> configurer.init(builder));

        ExceptionHandlingConfigurer<B> exceptionHandling = builder.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(
                    new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                    new OrRequestMatcher(
                            getRequestMatcher(OAuth2TokenEndpointConfigurer.class))
            );
        }
    }

    @Override
    public void configure(B builder) {
        configurers.values().forEach(configurer -> configurer.configure(builder));

        ProviderSettings providerSettings = OAuth2ConfigurerUtils.getProviderSettings(builder);
        ProviderContextFilter providerContextFilter = new ProviderContextFilter(providerSettings);
        builder.addFilterAfter(providerContextFilter, SecurityContextPersistenceFilter.class);
    }

    private Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> createConfigurers() {
        Map<Class<? extends AbstractOAuth2Configurer>, AbstractOAuth2Configurer> configurers = new LinkedHashMap<>();
        configurers.put(OAuth2ClientAuthenticationConfigurer.class, new OAuth2ClientAuthenticationConfigurer());
        configurers.put(OAuth2TokenEndpointConfigurer.class, new OAuth2TokenEndpointConfigurer());
        return configurers;
    }

    @SuppressWarnings("unchecked")
    private <T extends AbstractOAuth2Configurer> T getConfigurer(Class<T> configurerType) {
        return (T) configurers.get(configurerType);
    }

    private <T extends AbstractOAuth2Configurer> RequestMatcher getRequestMatcher(Class<T> configurerType) {
        return getConfigurer(configurerType).getRequestMatcher();
    }

    @SuppressWarnings("all")
    private static void validateProviderSettings(ProviderSettings providerSettings) {
        if (providerSettings.getIssuer() != null) {
            try {
                new URI(providerSettings.getIssuer()).toURL();
            } catch (Exception ex) {
                throw new IllegalArgumentException("issuer must be a valid URL", ex);
            }
        }
    }
}
