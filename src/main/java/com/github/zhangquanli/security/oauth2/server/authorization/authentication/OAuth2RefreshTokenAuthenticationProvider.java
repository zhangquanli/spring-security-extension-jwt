package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.function.Supplier;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Refresh Token Grant.
 *
 * @author Alexey Nesterov
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see OAuth2RefreshTokenAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see JwtEncoder
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-1.5" target="_blank">Section 1.5 Refresh Token Grant</a>
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-6" target="_blank">Section 6 Refreshing an Access Token</a>
 */
public final class OAuth2RefreshTokenAuthenticationProvider implements AuthenticationProvider {

    private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);

    private final JwtEncoder jwtEncoder;

    private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;

    /**
     * Constructs an {@code OAuth2RefreshTokenAuthenticationProvider} using the provided parameters.
     *
     * @param jwtEncoder the jwt encoder
     */
    public OAuth2RefreshTokenAuthenticationProvider(JwtEncoder jwtEncoder) {
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.jwtEncoder = jwtEncoder;
    }

    /**
     * Sets the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}.
     *
     * @param refreshTokenGenerator the {@code Supplier<String>} that generates the value for the {@link OAuth2RefreshToken}
     */
    public void setRefreshTokenGenerator(Supplier<String> refreshTokenGenerator) {
        Assert.notNull(refreshTokenGenerator, "refreshTokenGenerator cannot be null");
        this.refreshTokenGenerator = refreshTokenGenerator;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
//        OAuth2RefreshTokenAuthenticationToken refreshTokenAuthentication =
//                (OAuth2RefreshTokenAuthenticationToken) authentication;
//
//        OAuth2ClientAuthenticationToken clientPrincipal =
//                getAuthenticatedClientElseThrowInvalidClient(refreshTokenAuthentication);
//        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
//
//        OAuth2Authorization authorization = this.authorizationService.findByToken(
//                refreshTokenAuthentication.getRefreshToken(), OAuth2TokenType.REFRESH_TOKEN);
//        if (authorization == null) {
//            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
//        }
//
//        if (!registeredClient.getId().equals(authorization.getRegisteredClientId())) {
//            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
//        }
//
//        if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
//            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
//        }
//
//        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken = authorization.getRefreshToken();
//        if (!refreshToken.isActive()) {
//            // As per https://tools.ietf.org/html/rfc6749#section-5.2
//            // invalid_grant: The provided authorization grant (e.g., authorization code,
//            // resource owner credentials) or refresh token is invalid, expired, revoked [...].
//            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);
//        }
//
//        // As per https://tools.ietf.org/html/rfc6749#section-6
//        // The requested scope MUST NOT include any scope not originally granted by the resource owner,
//        // and if omitted is treated as equal to the scope originally granted by the resource owner.
//        Set<String> scopes = refreshTokenAuthentication.getScopes();
//        Set<String> authorizedScopes = authorization.getAttribute(OAuth2Authorization.AUTHORIZED_SCOPE_ATTRIBUTE_NAME);
//        if (!authorizedScopes.containsAll(scopes)) {
//            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_SCOPE);
//        }
//        if (scopes.isEmpty()) {
//            scopes = authorizedScopes;
//        }
//
//        String issuer = ProviderContextHolder.getProviderContext().getIssuer();
//
//        JoseHeader.Builder headersBuilder = JwtUtils.headers();
//        JwtClaimsSet.Builder claimsBuilder = JwtUtils.accessTokenClaims(
//                registeredClient, issuer, authorization.getPrincipalName(), scopes);
//
//        // @formatter:off
//        JwtEncodingContext context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
//                .registeredClient(registeredClient)
//                .principal(authorization.getAttribute(Principal.class.getName()))
//                .authorization(authorization)
//                .authorizedScopes(authorizedScopes)
//                .tokenType(OAuth2TokenType.ACCESS_TOKEN)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .authorizationGrant(refreshTokenAuthentication)
//                .build();
//        // @formatter:on
//
//        this.jwtCustomizer.customize(context);
//
//        JoseHeader headers = context.getHeaders().build();
//        JwtClaimsSet claims = context.getClaims().build();
//        Jwt jwtAccessToken = this.jwtEncoder.encode(headers, claims);
//
//        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
//                jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
//                jwtAccessToken.getExpiresAt(), scopes);
//
//        TokenSettings tokenSettings = registeredClient.getTokenSettings();
//
//        OAuth2RefreshToken currentRefreshToken = refreshToken.getToken();
//        if (!tokenSettings.isReuseRefreshTokens()) {
//            currentRefreshToken = generateRefreshToken(tokenSettings.getRefreshTokenTimeToLive());
//        }
//
//        Jwt jwtIdToken = null;
//        if (authorizedScopes.contains(OidcScopes.OPENID)) {
//            headersBuilder = JwtUtils.headers();
//            claimsBuilder = JwtUtils.idTokenClaims(
//                    registeredClient, issuer, authorization.getPrincipalName(), null);
//
//            // @formatter:off
//            context = JwtEncodingContext.with(headersBuilder, claimsBuilder)
//                    .registeredClient(registeredClient)
//                    .principal(authorization.getAttribute(Principal.class.getName()))
//                    .authorization(authorization)
//                    .authorizedScopes(authorizedScopes)
//                    .tokenType(ID_TOKEN_TOKEN_TYPE)
//                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                    .authorizationGrant(refreshTokenAuthentication)
//                    .build();
//            // @formatter:on
//
//            this.jwtCustomizer.customize(context);
//
//            headers = context.getHeaders().build();
//            claims = context.getClaims().build();
//            jwtIdToken = this.jwtEncoder.encode(headers, claims);
//        }
//
//        OidcIdToken idToken;
//        if (jwtIdToken != null) {
//            idToken = new OidcIdToken(jwtIdToken.getTokenValue(), jwtIdToken.getIssuedAt(),
//                    jwtIdToken.getExpiresAt(), jwtIdToken.getClaims());
//        } else {
//            idToken = null;
//        }
//
//        // @formatter:off
//        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization)
//                .token(accessToken,
//                        (metadata) -> {
//                            metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, jwtAccessToken.getClaims());
//                            metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, false);
//                        })
//                .refreshToken(currentRefreshToken);
//        if (idToken != null) {
//            authorizationBuilder
//                    .token(idToken,
//                            (metadata) ->
//                                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
//        }
//        authorization = authorizationBuilder.build();
//        // @formatter:on
//
//        this.authorizationService.save(authorization);
//
//        Map<String, Object> additionalParameters = Collections.emptyMap();
//        if (idToken != null) {
//            additionalParameters = new HashMap<>();
//            additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
//        }
//
//        return new OAuth2AccessTokenAuthenticationToken(
//                registeredClient, clientPrincipal, accessToken, currentRefreshToken, additionalParameters);
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2RefreshTokenAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(tokenTimeToLive);
        return new OAuth2RefreshToken(this.refreshTokenGenerator.get(), issuedAt, expiresAt);
    }
}
