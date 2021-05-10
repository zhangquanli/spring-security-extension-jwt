package com.github.zhangquanli.security;

import com.github.zhangquanli.security.jwt.*;
import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class AbstractJwtAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private Duration expiresIn = Duration.ofDays(7L);
    private JwtEncoder jwtEncoder = JwtUtil.defaultJwtEncoder();

    protected AbstractJwtAuthenticationProcessingFilter(RequestMatcher requiresAuthenticationRequestMatcher) {
        super(requiresAuthenticationRequestMatcher);
    }

    /**
     * Sets the jwtEncoder which will be used to generate the jwt.
     *
     * @param jwtEncoder the {@link JwtEncoder}
     */
    public void setJwtEncoder(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * Sets the expiresIn which will be used to expires the jwt.
     *
     * @param expiresIn the {@link Duration}
     */
    public void setExpiresIn(Duration expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        JoseHeader headers = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();
        String subject = authResult.getName();
        List<String> audience = Collections.singletonList(
                ((WebAuthenticationDetails) authResult.getDetails()).getRemoteAddress());
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(expiresIn);
        Set<String> scope = authResult.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(subject)
                .audience(audience)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .claim("scope", scope)
                .build();
        Jwt jwt = jwtEncoder.encode(headers, claims);
        ((AbstractJwtAuthenticationToken) authResult).setJwt(jwt);

        SecurityContextHolder.getContext().setAuthentication(authResult);
        if (logger.isDebugEnabled()) {
            logger.debug(LogMessage.format("Set SecurityContextHolder to %s", authResult));
        }
        getRememberMeServices().loginSuccess(request, response, authResult);
        if (eventPublisher != null) {
            eventPublisher.publishEvent(new InteractiveAuthenticationSuccessEvent(authResult, getClass()));
        }
        getSuccessHandler().onAuthenticationSuccess(request, response, authResult);
    }
}
