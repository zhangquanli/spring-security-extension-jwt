/*
 * Copyright 2020-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import com.github.zhangquanli.security.AbstractJwtAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.util.Assert;

import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * An {@link AuthenticationProvider} implementation for the OAuth 2.0 Password Grant.
 *
 * @author Joe Grandja
 * @author Daniel Garnier-Moiroux
 * @see OAuth2PasswordAuthenticationToken
 * @see OAuth2AccessTokenAuthenticationToken
 * @see JwtEncoder
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1" target="_blank">Section 4.1 Authorization Code Grant</a>
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-4.1.3" target="_blank">Section 4.1.3 Access Token Request</a>
 */
public final class OAuth2PasswordAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider {

    /**
     * The plaintext password used to perform {@link PasswordEncoder#matches(CharSequence, String)}
     * on when the user is not found to avoid SEC-2056.
     */
    private static final String USER_NOT_FOUND_PASSWORD = "userNotFoundPassword";

    /**
     * The password used to perform {@link PasswordEncoder#matches(CharSequence, String)}
     * on when the user is not found to avoid SEC-2056. This is necessary, because some
     * {@link PasswordEncoder} implementation will short circuit if the password is not
     * in valid format.
     */
    private volatile String userNotFoundEncodedPassword;

    private static final StringKeyGenerator DEFAULT_REFRESH_TOKEN_GENERATOR =
            new Base64StringKeyGenerator(Base64.getUrlEncoder().withoutPadding(), 96);
    private final JwtEncoder jwtEncoder;

    private Supplier<String> refreshTokenGenerator = DEFAULT_REFRESH_TOKEN_GENERATOR::generateKey;
    private UserDetailsService userDetailsService;
    private PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

    /**
     * Constructs an {@code OAuth2AuthorizationCodeAuthenticationProvider} using the provided parameters.
     *
     * @param jwtEncoder the jwt encoder
     */
    public OAuth2PasswordAuthenticationProvider(JwtEncoder jwtEncoder) {
        Assert.notNull(jwtEncoder, "jwtEncoder cannot be null");
        this.jwtEncoder = jwtEncoder;
    }

    @Override
    protected UserDetails retrieveUser(String username, AbstractJwtAuthenticationToken authentication)
            throws AuthenticationException {
        prepareTimingAttackProtection();
        UserDetails loadedUser = userDetailsService.loadUserByUsername(username);
        try {
            if (loadedUser == null) {
                throw new InternalAuthenticationServiceException(
                        "UserDetailsService returned null, which is an interface contract violation");
            }
            return loadedUser;
        } catch (UsernameNotFoundException ex) {
            mitigateAgainstTimingAttack(authentication);
            throw ex;
        } catch (InternalAuthenticationServiceException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex);
        }
    }

    private void prepareTimingAttackProtection() {
        if (userNotFoundEncodedPassword == null) {
            userNotFoundEncodedPassword = passwordEncoder.encode(USER_NOT_FOUND_PASSWORD);
        }
    }

    private void mitigateAgainstTimingAttack(Authentication authentication) {
        if (authentication.getCredentials() != null) {
            String presentPassword = authentication.getCredentials().toString();
            passwordEncoder.matches(presentPassword, userNotFoundEncodedPassword);
        }
    }

    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, AbstractJwtAuthenticationToken authentication) throws AuthenticationException {
        if (authentication.getCredentials() == null) {
            logger.debug("Failed to authenticate since no credentials provided");
            throw new BadCredentialsException("Bad credentials");
        }
        String presentedPassword = authentication.getCredentials().toString();
        if (!passwordEncoder.matches(presentedPassword, userDetails.getPassword())) {
            logger.debug("Failed to authenticate since password does not match stored value");
            throw new BadCredentialsException("Bad credentials");
        }
    }

    @Override
    protected Authentication createSuccessAuthentication(Authentication authentication, UserDetails user) throws AuthenticationException {
        OAuth2PasswordAuthenticationToken passwordAuthentication = (OAuth2PasswordAuthenticationToken) authentication;

        OAuth2ClientAuthenticationToken clientPrincipal = OAuth2AuthenticationProviderUtils
                .getAuthenticatedClientElseThrowInvalidClient(passwordAuthentication);

        Set<String> authorizedScopes = user.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).collect(Collectors.toSet());

        JwsHeader jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build();
        JwtClaimsSet jwtClaimsSet = generateJwtClaimSet(user.getUsername(), authorizedScopes);
        JwtEncoderParameters parameters = JwtEncoderParameters.from(jwsHeader, jwtClaimsSet);
        Jwt jwtAccessToken = jwtEncoder.encode(parameters);

        OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                jwtAccessToken.getTokenValue(), jwtAccessToken.getIssuedAt(),
                jwtAccessToken.getExpiresAt(), authorizedScopes);
        OAuth2RefreshToken refreshToken = generateRefreshToken(Duration.ofDays(7L));
        // TODO 保存 access_token 和 refresh_token
//        authorizationService.save(authorization);
        OAuth2AccessTokenAuthenticationToken result = new OAuth2AccessTokenAuthenticationToken(
                accessToken, refreshToken);
        result.setDetails(authentication.getDetails());
        logger.debug("Authenticated user");
        return result;
    }

    private JwtClaimsSet generateJwtClaimSet(String subject, Set<String> authorizedScopes) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(Duration.ofMinutes(30L));
        return JwtClaimsSet.builder()
                .issuer("authorization-server")
                .subject(subject)
                .audience(Collections.singletonList("authorization-server"))
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .notBefore(issuedAt)
                .claim(OAuth2ParameterNames.SCOPE, authorizedScopes)
                .build();
    }

    private OAuth2RefreshToken generateRefreshToken(Duration tokenTimeToLive) {
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(tokenTimeToLive);
        return new OAuth2RefreshToken(refreshTokenGenerator.get(), issuedAt, expiresAt);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2PasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setUserDetailsService(UserDetailsService userDetailsService) {
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.userDetailsService = userDetailsService;
    }

    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
        this.passwordEncoder = passwordEncoder;
        this.userNotFoundEncodedPassword = null;
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

}
