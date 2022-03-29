package com.github.zhangquanli.security.oauth2.server.authorization.web.authentication;

import com.github.zhangquanli.security.oauth2.server.authorization.authentication.OAuth2PasswordAuthenticationToken;
import com.github.zhangquanli.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.lang.Nullable;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

/**
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the OAuth 2.0 Authorization Code Grant
 * and then converts it to an {@link OAuth2PasswordAuthenticationToken} used for authenticating the authorization grant.
 *
 * @author Joe Grandja
 * @see AuthenticationConverter
 * @see OAuth2PasswordAuthenticationToken
 * @see OAuth2TokenEndpointFilter
 */
public final class OAuth2PasswordAuthenticationConverter implements AuthenticationConverter {
    @Nullable
    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

        // username (REQUIRED)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (!StringUtils.hasText(username) ||
                parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.USERNAME,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // password (REQUIRED)
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (StringUtils.hasText(password) &&
                parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
            OAuth2EndpointUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.PASSWORD,
                    OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                    !key.equals(OAuth2ParameterNames.CLIENT_ID) &&
                    !key.equals(OAuth2ParameterNames.USERNAME) &&
                    !key.equals(OAuth2ParameterNames.PASSWORD)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        return new OAuth2PasswordAuthenticationToken(
                username, password, clientPrincipal, additionalParameters);
    }
}
