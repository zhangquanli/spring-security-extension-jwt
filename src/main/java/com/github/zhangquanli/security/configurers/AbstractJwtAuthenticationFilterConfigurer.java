package com.github.zhangquanli.security.configurers;

import com.github.zhangquanli.security.AbstractJwtAuthenticationProcessingFilter;
import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
import com.github.zhangquanli.security.JwtAuthenticationFailureHandler;
import com.github.zhangquanli.security.JwtAuthenticationSuccessHandler;
import com.github.zhangquanli.security.jwt.JwtUtil;
import com.github.zhangquanli.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.context.ApplicationContext;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T loginProcessingUrl(String loginProcessingUrl) {
        authFilter.setRequiresAuthenticationRequestMatcher(
                new AntPathRequestMatcher(loginProcessingUrl, "POST"));
        return getSelf();
    }

    /**
     * Specifies a custom {@link AuthenticationDetailsSource}. The default is
     * {@link WebAuthenticationDetailsSource}.
     *
     * @param authenticationDetailsSource the custom {@link AuthenticationDetailsSource}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T authenticationDetailsSource(
            AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource) {
        authFilter.setAuthenticationDetailsSource(authenticationDetailsSource);
        return getSelf();
    }

    /**
     * Specifies the {@link Converter} to use when authentication convert to claims.
     *
     * @param jwtClaimsSetConverter the {@link Converter}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T jwtClaimsSetConverter(
            Converter<AbstractJwtAuthenticationToken, JwtClaimsSet> jwtClaimsSetConverter) {
        authFilter.setJwtClaimsSetConverter(jwtClaimsSetConverter);
        return getSelf();
    }

    /**
     * Specifies the {@link JwtEncoder} to use when jwt generates.
     *
     * @param jwtEncoder the {@link JwtEncoder}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T jwtEncoder(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
        return getSelf();
    }

    /**
     * Specifies the {@link Duration} to use when jwt expires.
     *
     * @param expiresIn the {@link Duration}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T expiresIn(Duration expiresIn) {
        authFilter.setExpiresIn(expiresIn);
        return getSelf();
    }

    /**
     * Specifies the {@link AuthenticationSuccessHandler} to be use when authentication
     * successes.
     *
     * @param successHandler the {@link AuthenticationSuccessHandler}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T successHandler(AuthenticationSuccessHandler successHandler) {
        authFilter.setSuccessHandler(successHandler);
        return getSelf();
    }

    /**
     * Specifies the {@link AuthenticationFailureHandler} to use when authentication
     * fails.
     *
     * @param failureHandler the {@link AuthenticationFailureHandler}
     * @return the {@link AbstractJwtAuthenticationFilterConfigurer} for
     * additional customization
     */
    public final T failureHandler(AuthenticationFailureHandler failureHandler) {
        authFilter.setFailureHandler(failureHandler);
        return getSelf();
    }

    @Override
    public void init(B http) {
        registerDefaultAuthenticationEntryPoint(http);
        disableCsrf(http);
    }

    @Override
    public void configure(B http) {
        authFilter.setJwtEncoder(getJwtEncoder(http));
        authFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        F filter = postProcess(authFilter);
        http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * Gets the Authentication Filter
     *
     * @return the Authentication Filter
     */
    protected final F getAuthenticationFilter() {
        return authFilter;
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
    private void disableCsrf(B http) {
        http.removeConfigurer(CsrfConfigurer.class);
    }

    @SuppressWarnings("unchecked")
    private T getSelf() {
        return (T) this;
    }
}
