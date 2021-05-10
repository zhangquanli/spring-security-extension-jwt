package com.github.zhangquanli.security.jwt;

import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Set;

public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    private static final StringKeyGenerator TOKEN_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    private final HttpMessageConverter<OAuth2AccessTokenResponse> accessTokenHttpResponseConverter =
            new OAuth2AccessTokenResponseHttpMessageConverter();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        Jwt jwt = ((AbstractJwtAuthenticationToken) authentication).getJwt();
        Instant issuedAt = jwt.getIssuedAt();
        assert issuedAt != null;
        Instant expiresAt = jwt.getExpiresAt();
        assert expiresAt != null;
        Set<String> scope = jwt.getClaim("scope");

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
