package com.github.zhangquanli.security.configurers;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

/**
 * {@link Configuration} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @see OAuth2AuthorizationServerConfigurer
 */
public class OAuth2AuthorizationServerConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<OAuth2AuthorizationServerConfigurer<H>, H> {

    /**
     * Configures the OAuth 2.0 Token Endpoint.
     *
     * @param tokenEndpointCustomizer the {@link Customizer} providing access to the {@link OAuth2TokenEndpointConfigurer}
     * @return the {@link OAuth2AuthorizationServerConfigurer} for further configuration
     */
    public OAuth2AuthorizationServerConfigurer<H> tokenEndpoint(Customizer<OAuth2TokenEndpointConfigurer> tokenEndpointCustomizer) {
//        tokenEndpointCustomizer.customize(getConfigurer(OAuth2TokenEndpointConfigurer.class));
        return this;
    }
}
