package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.jwt.*;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.*;
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
    private JwtEncoder jwtEncoder;

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
     * Specifies the {@link JwtEncoder} to use when jwt generates.
     *
     * @param jwtEncoder the {@link JwtEncoder}
     * @return the {@link PasswordLoginConfigurer} for additional customization
     */
    public final T jwtEncoder(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
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
        authFilter.setJwtEncoder(getJwtEncoder(http));
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
        http.addFilterAfter(filter, UsernamePasswordAuthenticationFilter.class);
    }

    private JwtEncoder getJwtEncoder(B http) {
        if (jwtEncoder == null) {
            ApplicationContext context = http.getSharedObject(ApplicationContext.class);
            if (context.getBeanNamesForType(JwtEncoder.class).length > 0) {
                jwtEncoder = context.getBean(JwtEncoder.class);
            } else {
                jwtEncoder = http.getSharedObject(JwtEncoder.class);
                if (jwtEncoder == null) {
                    jwtEncoder = JwtUtil.defaultJwtEncoder();
                    http.setSharedObject(JwtEncoder.class, jwtEncoder);
                }
            }
        }
        return jwtEncoder;
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
