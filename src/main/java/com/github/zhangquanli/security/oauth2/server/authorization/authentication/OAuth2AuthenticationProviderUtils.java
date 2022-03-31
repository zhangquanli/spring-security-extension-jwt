package com.github.zhangquanli.security.oauth2.server.authorization.authentication;

import com.github.zhangquanli.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.*;

/**
 * Utility methods for the OAuth 2.0 {@link AuthenticationProvider}'s.
 *
 * @author Joe Grandja
 */
final class OAuth2AuthenticationProviderUtils {
    private OAuth2AuthenticationProviderUtils() {
    }

    static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;
        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }
        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }
        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }

    static <T extends AbstractOAuth2Token> OAuth2Authorization invalidate(
            OAuth2Authorization authorization, T token) {

        OAuth2Authorization.Builder builder = OAuth2Authorization.from(authorization)
                .token(token, (metadata) ->
                        metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));

        if (OAuth2RefreshToken.class.isAssignableFrom(token.getClass())) {
            OAuth2AccessToken accessToken = authorization.getAccessToken().getToken();
            builder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.INVALIDATED_METADATA_NAME, true));
        }

        return builder.build();
    }
}
