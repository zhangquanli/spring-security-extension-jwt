package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.jwt.JwtUtil;
import com.github.zhangquanli.security.token.authentication.JwtAuthenticationConverter;
import com.github.zhangquanli.security.token.authentication.JwtAuthenticationProvider;
import com.github.zhangquanli.security.token.web.*;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;

public final class JwtConfigurer<H extends HttpSecurityBuilder<H>>
        extends AbstractHttpConfigurer<JwtConfigurer<H>, H> {
    private AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver;
    private BearerTokenResolver bearerTokenResolver;
    private JwtDecoder jwtDecoder;
    private AccessDeniedHandler accessDeniedHandler = new BearerTokenAccessDeniedHandler();
    private AuthenticationEntryPoint authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
    private final BearerTokenRequestMatcher requestMatcher = new BearerTokenRequestMatcher();

    public JwtConfigurer<H> authenticationManagerResolver(
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
        Assert.notNull(authenticationManagerResolver, "authenticationManagerResolver cannot be null");
        this.authenticationManagerResolver = authenticationManagerResolver;
        return this;
    }

    public JwtConfigurer<H> bearerTokenResolver(BearerTokenResolver bearerTokenResolver) {
        Assert.notNull(bearerTokenResolver, "bearerTokenResolver cannot be null");
        this.bearerTokenResolver = bearerTokenResolver;
        return this;
    }

    public JwtConfigurer<H> jwtDecoder(JwtDecoder jwtDecoder) {
        Assert.notNull(jwtDecoder, "jwtDecoder cannot be null");
        this.jwtDecoder = jwtDecoder;
        return this;
    }

    public JwtConfigurer<H> accessDeniedHandler(AccessDeniedHandler accessDeniedHandler) {
        Assert.notNull(accessDeniedHandler, "accessDeniedHandler cannot be null");
        this.accessDeniedHandler = accessDeniedHandler;
        return this;
    }

    public JwtConfigurer<H> authenticationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint) {
        Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint");
        this.authenticationEntryPoint = authenticationEntryPoint;
        return this;
    }

    @Override
    public void init(H http) {
        registerDefaultAccessDeniedHandler(http);
        registerDefaultAuthenticationEntryPoint(http);
        AuthenticationProvider authenticationProvider = getAuthenticationProvider(http);
        http.authenticationProvider(authenticationProvider);
    }

    @Override
    public void configure(H http) {
        BearerTokenResolver bearerTokenResolver = getBearerTokenResolver(http);
        requestMatcher.setBearerTokenResolver(bearerTokenResolver);
        AuthenticationManagerResolver<HttpServletRequest> resolver = authenticationManagerResolver;
        if (resolver == null) {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            resolver = request -> authenticationManager;
        }
        BearerTokenAuthenticationFilter filter = new BearerTokenAuthenticationFilter(resolver);
        filter.setBearerTokenResolver(bearerTokenResolver);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);
        filter = postProcess(filter);
        http.addFilterAfter(filter, UsernamePasswordAuthenticationFilter.class);
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultAccessDeniedHandler(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAccessDeniedHandlerFor(accessDeniedHandler, requestMatcher);
        }
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultAuthenticationEntryPoint(H http) {
        ExceptionHandlingConfigurer<H> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(authenticationEntryPoint, requestMatcher);
        }
    }

    private AuthenticationProvider getAuthenticationProvider(H http) {
        JwtDecoder jwtDecoder = getJwtDecoder(http);
        ApplicationContext context = http.getSharedObject(ApplicationContext.class);
        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(jwtDecoder);
        if (context.getBeanNamesForType(JwtAuthenticationConverter.class).length > 0) {
            provider.setJwtAuthenticationConverter(context.getBean(JwtAuthenticationConverter.class));
        } else {
            provider.setJwtAuthenticationConverter(new JwtAuthenticationConverter());
        }
        return provider;
    }

    private JwtDecoder getJwtDecoder(H http) {
        if (jwtDecoder == null) {
            ApplicationContext context = http.getSharedObject(ApplicationContext.class);
            if (context.getBeanNamesForType(JwtDecoder.class).length > 0) {
                jwtDecoder = context.getBean(JwtDecoder.class);
            } else {
                jwtDecoder = http.getSharedObject(JwtDecoder.class);
                if (jwtDecoder == null) {
                    jwtDecoder = JwtUtil.defaultJwtDecoder();
                    http.setSharedObject(JwtDecoder.class, jwtDecoder);
                }
            }
        }
        return jwtDecoder;
    }

    private BearerTokenResolver getBearerTokenResolver(H http) {
        if (bearerTokenResolver == null) {
            ApplicationContext context = http.getSharedObject(ApplicationContext.class);
            if (context.getBeanNamesForType(BearerTokenResolver.class).length > 0) {
                bearerTokenResolver = context.getBean(BearerTokenResolver.class);
            } else {
                bearerTokenResolver = new DefaultBearerTokenResolver();
            }
        }
        return bearerTokenResolver;
    }

    private static class BearerTokenRequestMatcher implements RequestMatcher {
        private BearerTokenResolver bearerTokenResolver;

        @Override
        public boolean matches(HttpServletRequest request) {
            try {
                return bearerTokenResolver.resolve(request) != null;
            } catch (OAuth2AuthenticationException ex) {
                return false;
            }
        }

        void setBearerTokenResolver(BearerTokenResolver tokenResolver) {
            Assert.notNull(tokenResolver, "resolver cannot be null");
            this.bearerTokenResolver = tokenResolver;
        }
    }
}
