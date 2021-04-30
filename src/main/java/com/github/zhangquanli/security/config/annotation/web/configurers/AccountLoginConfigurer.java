package com.github.zhangquanli.security.config.annotation.web.configurers;

import com.github.zhangquanli.security.web.authentication.JwtAuthenticationFailureHandler;
import com.github.zhangquanli.security.web.authentication.JwtAuthenticationSuccessHandler;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;

public final class AccountLoginConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractHttpConfigurer<AccountLoginConfigurer<H>, H> {
    private final KeyPair keyPair = generateRsaKey();
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource = new WebAuthenticationDetailsSource();
    private final JwtAuthenticationSuccessHandler successHandler = new JwtAuthenticationSuccessHandler(keyPair);
    private final JwtAuthenticationFailureHandler failureHandler = new JwtAuthenticationFailureHandler();
    private final BearerTokenResolver bearerTokenResolver = new DefaultBearerTokenResolver();
    private final AccessDeniedHandler accessDeniedHandler = new BearerTokenAccessDeniedHandler();
    private final AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
    private final BearerTokenRequestMatcher bearerTokenRequestMatcher = new BearerTokenRequestMatcher();

    private UsernamePasswordAuthenticationFilter authFilter;

    public AccountLoginConfigurer() {
        authFilter = new UsernamePasswordAuthenticationFilter();
        loginProcessingUrl("/account/login");
        usernameParameter("username");
        passwordParameter("password");
        expiresIn(Duration.ofDays(7L));
    }

    /**
     * Specifies the URL to validate the credentials.
     *
     * @param loginProcessingUrl the URL to validate username and password
     * @return the {@link AccountLoginConfigurer} for additional customization
     */
    public AccountLoginConfigurer<H> loginProcessingUrl(String loginProcessingUrl) {
        RequestMatcher requestMatcher = new AntPathRequestMatcher(loginProcessingUrl, "POST");
        authFilter.setRequiresAuthenticationRequestMatcher(requestMatcher);
        return this;
    }

    /**
     * The HTTP parameter to look for the username when performing authentication. Default
     * is "username".
     *
     * @param usernameParameter the HTTP parameter to look for the username when
     *                          performing authentication
     * @return the {@link AccountLoginConfigurer} for additional customization
     */
    public AccountLoginConfigurer<H> usernameParameter(String usernameParameter) {
        authFilter.setUsernameParameter(usernameParameter);
        return this;
    }

    /**
     * The HTTP parameter to look for the password when performing authentication. Default
     * is "password".
     *
     * @param passwordParameter the HTTP parameter to look for the password when
     *                          performing authentication
     * @return the {@link AccountLoginConfigurer} for additional customization
     */
    public AccountLoginConfigurer<H> passwordParameter(String passwordParameter) {
        authFilter.setPasswordParameter(passwordParameter);
        return this;
    }

    /**
     * Set the JWT expires after the expired time.
     *
     * @param expiresIn the expired time
     * @return the {@link AccountLoginConfigurer} for additional customization
     */
    public AccountLoginConfigurer<H> expiresIn(Duration expiresIn) {
        successHandler.setExpiresIn(expiresIn);
        return this;
    }

    @Override
    public void init(H http) {
        registerDefaultAccessDeniedHandler(http);
        registerDefaultEntryPoint(http);
        registerDefaultCsrfOverride(http);
        registerDefaultAuthenticationProvider(http);
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultAccessDeniedHandler(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAccessDeniedHandlerFor(accessDeniedHandler, bearerTokenRequestMatcher);
        }
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultEntryPoint(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(authenticationEntryPoint, bearerTokenRequestMatcher);
        }
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultCsrfOverride(H http) {
        CsrfConfigurer<H> csrf = http.getConfigurer(CsrfConfigurer.class);
        if (csrf != null) {
            csrf.ignoringRequestMatchers(bearerTokenRequestMatcher);
        }
    }

    private void registerDefaultAuthenticationProvider(H http) {
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        JwtDecoder jwtDecoder = NimbusJwtDecoder.withPublicKey(rsaPublicKey).build();
        AuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
        http.authenticationProvider(provider);
    }

    @Override
    public void configure(H http) {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
        authFilter.setAuthenticationManager(authenticationManager);
        authFilter.setAuthenticationSuccessHandler(successHandler);
        authFilter.setAuthenticationFailureHandler(failureHandler);
        authFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        authFilter = postProcess(authFilter);
        http.addFilter(authFilter);

        bearerTokenRequestMatcher.setBearerTokenResolver(bearerTokenResolver);
        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(authenticationManager);
        filter = postProcess(filter);
        http.addFilter(filter);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static class BearerTokenRequestMatcher implements RequestMatcher {
        private BearerTokenResolver bearerTokenResolver;

        @Override
        public boolean matches(HttpServletRequest request) {
            try {
                return bearerTokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException e) {
                return false;
            }
        }

        void setBearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
            Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
            this.bearerTokenResolver = bearerTokenResolver;
        }
    }
}
