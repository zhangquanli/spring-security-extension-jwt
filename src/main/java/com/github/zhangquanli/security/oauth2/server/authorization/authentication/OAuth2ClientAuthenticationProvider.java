package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import com.github.zhangquanli.security.oauth2.server.authorization.OAuth2AuthorizationService;
import com.github.zhangquanli.security.oauth2.server.authorization.client.RegisteredClient;
import com.github.zhangquanli.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationProvider} implementation used for authenticating an OAuth 2.0 Client.
 *
 * @author Joe Grandja
 * @author Patryk Kostrzewa
 * @author Daniel Garnier-Moiroux
 * @author Rafal Lewczuk
 * @see AuthenticationProvider
 * @see OAuth2ClientAuthenticationToken
 * @see RegisteredClientRepository
 * @see OAuth2AuthorizationService
 * @see PasswordEncoder
 */
public class OAuth2ClientAuthenticationProvider implements AuthenticationProvider {
    private static final String CLIENT_AUTHENTICATION_ERROR_URI = "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-04#section-3.2.1";
    private final RegisteredClientRepository registeredClientRepository;
    private PasswordEncoder passwordEncoder;

    /**
     * Constructs an {@code OAuth2ClientAuthenticationProvider} using the provided parameters.
     *
     * @param registeredClientRepository the repository of registered clients
     */
    public OAuth2ClientAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
        Assert.notNull(registeredClientRepository, "registeredClientRepository cannot be null");
        this.registeredClientRepository = registeredClientRepository;
        this.passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * Sets the {@link PasswordEncoder} used to validate
     * the {@link RegisteredClient#getClientSecret() client secret}.
     * If not set, the client secret will be compared using
     * {@link PasswordEncoderFactories#createDelegatingPasswordEncoder()}.
     *
     * @param passwordEncoder the {@link PasswordEncoder} used to validate the client secret
     */
    public void setPasswordEncoder(PasswordEncoder passwordEncoder) {
        Assert.notNull(passwordEncoder, "passwordEncoder cannot be null");
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        OAuth2ClientAuthenticationToken clientAuthentication =
                (OAuth2ClientAuthenticationToken) authentication;

        String clientId = clientAuthentication.getPrincipal().toString();
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                    "client authentication failed: " + OAuth2ParameterNames.CLIENT_ID,
                    CLIENT_AUTHENTICATION_ERROR_URI);
            throw new OAuth2AuthenticationException(error, error.toString(), null);
        }

        if (!registeredClient.getClientAuthenticationMethods().contains(
                clientAuthentication.getClientAuthenticationMethod())) {
            throwInvalidClient("authentication_method");
        }

        if (clientAuthentication.getCredentials() != null) {
            String clientSecret = clientAuthentication.getCredentials().toString();
            if (!passwordEncoder.matches(clientSecret, registeredClient.getClientSecret())) {
                throwInvalidClient(OAuth2ParameterNames.CLIENT_SECRET);
            }
        }

        return new OAuth2ClientAuthenticationToken(registeredClient,
                clientAuthentication.getClientAuthenticationMethod(), clientAuthentication.getCredentials());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private void throwInvalidClient(String parameterName) throws OAuth2AuthenticationException {
        OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT,
                "client authentication failed: " + parameterName,
                CLIENT_AUTHENTICATION_ERROR_URI);
        throw new OAuth2AuthenticationException(error, error.toString(), null);
    }
}
