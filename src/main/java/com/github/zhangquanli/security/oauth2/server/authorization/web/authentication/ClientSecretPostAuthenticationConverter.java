package com.github.zhangquanli.security.oauth2.server.authorization.web.authentication;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Attempts to extract client credentials from POST parameters of {@link HttpServletRequest}
 * and then converts to an {@link OAuth2ClientAuthenticationToken} used for authenticating the client.
 *
 * @author Anoop Garlapati
 * @see AuthenticationConverter
 * @see OAuth2ClientAuthenticationToken
 * @see OAuth2ClientAuthenticationFilter
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-2.3.1" target="_blank">Section 2.3.1 Client Password</a>
 */
public final class ClientSecretPostAuthenticationConverter implements AuthenticationConverter {
    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // client_id (REQUIRED)
        String clientId = parameters.getFirst(OAuth2ParameterNames.CLIENT_ID);
        if (!StringUtils.hasText(clientId)) {
            return null;
        }

        if (parameters.get(OAuth2ParameterNames.CLIENT_ID).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        // client_secret (REQUIRED)
        String clientSecret = parameters.getFirst(OAuth2ParameterNames.CLIENT_SECRET);
        if (!StringUtils.hasText(clientSecret)) {
            return null;
        }

        if (parameters.get(OAuth2ParameterNames.CLIENT_SECRET).size() != 1) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_REQUEST);
        }

        Map<String, Object> additionalParameters = OAuth2EndpointUtils.getParametersIfMatchesAuthorizationCodeGrantRequest(request,
                OAuth2ParameterNames.CLIENT_ID,
                OAuth2ParameterNames.CLIENT_SECRET);

        return new OAuth2ClientAuthenticationToken(clientId, ClientAuthenticationMethod.CLIENT_SECRET_POST, clientSecret,
                additionalParameters);
    }
}
