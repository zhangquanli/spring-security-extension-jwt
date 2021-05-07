package com.github.zhangquanli.security.config.annotation.web.configurers;

import com.github.zhangquanli.security.AbstractJwtAuthenticationProcessingFilter;
import com.github.zhangquanli.security.jwt.JwtAuthenticationFailureHandler;
import com.github.zhangquanli.security.jwt.JwtAuthenticationSuccessHandler;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.*;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;

import javax.servlet.http.HttpServletRequest;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;

public abstract class AbstractJwtAuthenticationFilterConfigurer<B extends HttpSecurityBuilder<B>,
        T extends AbstractJwtAuthenticationFilterConfigurer<B, T, F>,
        F extends AbstractJwtAuthenticationProcessingFilter> extends AbstractHttpConfigurer<T, B> {
    private final F authFilter;
    private RequestMatcher loginProcessingRequestMatcher;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public AbstractJwtAuthenticationFilterConfigurer(F authenticationFilter, String loginProcessingUrl) {
        this.authFilter = authenticationFilter;
        this.authenticationEntryPoint = new BearerTokenAuthenticationEntryPoint();
        loginProcessingUrl(loginProcessingUrl);
        successHandler(new JwtAuthenticationSuccessHandler());
        failureHandler(new JwtAuthenticationFailureHandler());
        authenticationDetailsSource(new WebAuthenticationDetailsSource());
        expiresIn(Duration.ofDays(7L));
    }

    /**
     * Specifies the URL to validate the credentials.
     *
     * @param loginProcessingUrl the URL to validate username and password
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final T loginProcessingUrl(String loginProcessingUrl) {
        loginProcessingRequestMatcher = new AntPathRequestMatcher(loginProcessingUrl, "POST");
        authFilter.setRequiresAuthenticationRequestMatcher(loginProcessingRequestMatcher);
        return getSelf();
    }

    /**
     * Specifies the {@link AuthenticationSuccessHandler} to be use when authentication
     * successes.
     *
     * @param successHandler the {@link AuthenticationSuccessHandler}
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final T successHandler(AuthenticationSuccessHandler successHandler) {
        authFilter.setAuthenticationSuccessHandler(successHandler);
        return getSelf();
    }

    /**
     * Specifies the {@link AuthenticationFailureHandler} to use when authentication
     * fails.
     *
     * @param failureHandler the {@link AuthenticationFailureHandler}
     * @return the {@link PasswordLoginConfigurer} fro additional customization
     */
    public final T failureHandler(AuthenticationFailureHandler failureHandler) {
        authFilter.setAuthenticationFailureHandler(failureHandler);
        return getSelf();
    }

    /**
     * Specifies a custom {@link AuthenticationDetailsSource}. The default is
     * {@link WebAuthenticationDetailsSource}.
     *
     * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final T authenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        authFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        return getSelf();
    }


    /**
     * Specifies the {@link Duration} to use when jwt expires.
     *
     * @param expiresIn the {@link Duration}
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final T expiresIn(Duration expiresIn) {
        authFilter.setExpiresIn(expiresIn);
        return getSelf();
    }

    @Override
    public void init(B http) {
        registerDefaultCsrfOverride(http);
        registerDefaultAuthenticationEntryPoint(http);
    }

    @Override
    public void configure(B http) {
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        SessionAuthenticationStrategy sessionAuthenticationStrategy = http
                .getSharedObject(SessionAuthenticationStrategy.class);
        if (sessionAuthenticationStrategy != null) {
            this.authFilter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
        }
        RememberMeServices rememberMeServices = http.getSharedObject(RememberMeServices.class);
        if (rememberMeServices != null) {
            this.authFilter.setRememberMeServices(rememberMeServices);
        }
        F filter = postProcess(this.authFilter);
        http.addFilter(filter);
    }

    /**
     * Gets the Authentication Filter
     *
     * @return the Authentication Filter
     */
    protected final F getAuthenticationFilter() {
        return this.authFilter;
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultCsrfOverride(B http) {
        CsrfConfigurer<B> csrf = http.getConfigurer(CsrfConfigurer.class);
        if (csrf != null) {
            csrf.ignoringRequestMatchers(loginProcessingRequestMatcher);
        }
    }

    @SuppressWarnings("unchecked")
    private void registerDefaultAuthenticationEntryPoint(B http) {
        ExceptionHandlingConfigurer<B> exceptionHandling = http.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(postProcess(authenticationEntryPoint),
                    getAuthenticationEntryPointMatcher(http));
        }
    }


    private RequestMatcher getAuthenticationEntryPointMatcher(B http) {
        ContentNegotiationStrategy contentNegotiationStrategy = http.getSharedObject(ContentNegotiationStrategy.class);
        if (contentNegotiationStrategy == null) {
            contentNegotiationStrategy = new HeaderContentNegotiationStrategy();
        }
        MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
                MediaType.APPLICATION_XHTML_XML, new MediaType("image", "*"), MediaType.TEXT_HTML,
                MediaType.TEXT_PLAIN);
        mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));
        RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
                new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));
        return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
    }

    @SuppressWarnings("unchecked")
    private T getSelf() {
        return (T) this;
    }
}
