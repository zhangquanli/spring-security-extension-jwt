package com.github.zhangquanli.security.oauth2.server.authorization.web.authentication;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.http.HttpHeaders;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Attempts to extract HTTP Basic credentials from {@link HttpServletRequest}
 * and then converts to an {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
 *
 * @author Patryk Kostrzewa
 * @author Joe Grandja
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 */
public final class ClientSecretBasicAuthenticationConverter implements AuthenticationConverter {
    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null) {
            return null;
        }

        String[] parts = header.split("\\s");
        if (!parts[0].equalsIgnoreCase("Basic")) {
            return null;
        }

        if (parts.length != 2) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        byte[] decodedCredentials;
        try {
            decodedCredentials = Base64.getDecoder().decode(
                    parts[1].getBytes(StandardCharsets.UTF_8));
        } catch (IllegalArgumentException ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
        }

        String credentialsString = new String(decodedCredentials, StandardCharsets.UTF_8);
        String[] credentials = credentialsString.split(":", 2);
        if (credentials.length != 2 ||
                !StringUtils.hasText(credentials[0]) ||
                !StringUtils.hasText(credentials[1])) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        String clientId;
        String clientSecret;
        try {
            clientId = URLDecoder.decode(credentials[0], StandardCharsets.UTF_8.name());
            clientSecret = URLDecoder.decode(credentials[1], StandardCharsets.UTF_8.name());
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), ex);
        }

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientSecret,
                OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(request));
    }
}
