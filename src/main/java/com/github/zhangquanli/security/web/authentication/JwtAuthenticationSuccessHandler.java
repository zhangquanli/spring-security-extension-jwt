package com.github.zhangquanli.security.web.authentication;

import com.github.zhangquanli.security.oauth2.jwt.JoseHeader;
import com.github.zhangquanli.security.oauth2.jwt.JwtClaimsSet;
import com.github.zhangquanli.security.oauth2.jwt.JwtEncoder;
import com.github.zhangquanli.security.oauth2.jwt.NimbusJwsEncoder;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final StringKeyGenerator TOKEN_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();
    private final JwtEncoder jwtEncoder;
    private Duration expiresIn = Duration.ofDays(7L);

    public JwtAuthenticationSuccessHandler(KeyPair keyPair) {
        Assert.notNull(keyPair, "keyPair cannot be null");
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        JWKSource<SecurityContext> jwkSource = (jwkSelector, context) -> jwkSelector.select(jwkSet);
        this.jwtEncoder = new NimbusJwsEncoder(jwkSource);
    }

    public void setExpiresIn(Duration expiresIn) {
        this.expiresIn = expiresIn;
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        JoseHeader headers = JoseHeader.withAlgorithm(SignatureAlgorithm.RS256).build();

        String subject = authentication.getName();
        List<String> audience = Collections.singletonList(
                ((WebAuthenticationDetails) authentication.getDetails()).getRemoteAddress());
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(expiresIn);
        Set<String> scope = authentication.getAuthorities().stream()
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

        OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken(jwt.getTokenValue())
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .scopes(scope)
                .expiresIn(ChronoUnit.SECONDS.between(issuedAt, expiresAt))
                .refreshToken(TOKEN_GENERATOR.generateKey())
                .build();

        ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
        accessTokenHttpResponseConverter.write(accessTokenResponse, null, httpResponse);
    }
}
