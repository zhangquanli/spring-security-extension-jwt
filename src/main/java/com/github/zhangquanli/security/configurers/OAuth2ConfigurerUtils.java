package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.jwt.JwtUtil;
import com.github.zhangquanli.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import com.github.zhangquanli.security.oauth2.server.authorization.OAuth2AuthorizationService;
import com.github.zhangquanli.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Utility methods for the OAuth 2.0 Configurers.
 *
 * @author Joe Grandja
 */
final class OAuth2ConfigurerUtils {

    private OAuth2ConfigurerUtils() {
    }

    static <B extends HttpSecurityBuilder<B>> RegisteredClientRepository getRegisteredClientRepository(B builder) {
        RegisteredClientRepository registeredClientRepository = builder.getSharedObject(RegisteredClientRepository.class);
        if (registeredClientRepository == null) {
            registeredClientRepository = getBean(builder, RegisteredClientRepository.class);
            builder.setSharedObject(RegisteredClientRepository.class, registeredClientRepository);
        }
        return registeredClientRepository;
    }

    static <B extends HttpSecurityBuilder<B>> OAuth2AuthorizationService getAuthorizationService(B builder) {
        OAuth2AuthorizationService authorizationService = builder.getSharedObject(OAuth2AuthorizationService.class);
        if (authorizationService == null) {
            authorizationService = getOptionalBean(builder, OAuth2AuthorizationService.class);
            if (authorizationService == null) {
                authorizationService = new InMemoryOAuth2AuthorizationService();
            }
            builder.setSharedObject(OAuth2AuthorizationService.class, authorizationService);
        }
        return authorizationService;
    }

    static <B extends HttpSecurityBuilder<B>> UserDetailsService getUserDetailsService(B builder) {
        UserDetailsService userDetailsService = builder.getSharedObject(UserDetailsService.class);
        if (userDetailsService == null) {
            userDetailsService = getBean(builder, UserDetailsService.class);
            builder.setSharedObject(UserDetailsService.class, userDetailsService);
        }
        return userDetailsService;
    }

    static <B extends HttpSecurityBuilder<B>> JwtEncoder getJwtEncoder(B builder) {
        JwtEncoder jwtEncoder = builder.getSharedObject(JwtEncoder.class);
        if (jwtEncoder == null) {
            jwtEncoder = getOptionalBean(builder, JwtEncoder.class);
            if (jwtEncoder == null) {
                jwtEncoder = JwtUtil.defaultJwtEncoder();
            }
            builder.setSharedObject(JwtEncoder.class, jwtEncoder);
        }
        return jwtEncoder;
    }

    static <B extends HttpSecurityBuilder<B>, T> T getBean(B builder, Class<T> type) {
        return builder.getSharedObject(ApplicationContext.class).getBean(type);
    }

    static <B extends HttpSecurityBuilder<B>, T> T getOptionalBean(B builder, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors(
                builder.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            throw new NoUniqueBeanDefinitionException(type, beansMap.size(),
                    "Expected single matching bean of type '" + type.getName() + "' but found " +
                            beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        }
        return (!beansMap.isEmpty() ? beansMap.values().iterator().next() : null);
    }
}