package com.github.zhangquanli.security.oauth2.server.authorization;

import com.github.zhangquanli.security.oauth2.core.OAuth2TokenType;
import org.springframework.lang.Nullable;

/**
 * Implementations of this interface are responsible for the management
 * of {@link OAuth2Authorization OAuth 2.0 Authorization(s)}.
 *
 * @author Joe Grandja
 * @see OAuth2Authorization
 * @see OAuth2TokenType
 */
public interface OAuth2AuthorizationService {

    /**
     * Saves the {@link OAuth2Authorization}.
     *
     * @param authorization the {@link OAuth2Authorization}
     */
    void save(OAuth2Authorization authorization);

    /**
     * Removes the {@link OAuth2Authorization}.
     *
     * @param authorization the {@link OAuth2Authorization}
     */
    void remove(OAuth2Authorization authorization);

    /**
     * Returns the {@link OAuth2Authorization} identified by the provided {@code id},
     * or {@code null} if not found.
     *
     * @param id the authorization identifier
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    @Nullable
    OAuth2Authorization findById(String id);

    /**
     * Returns the {@link OAuth2Authorization} containing the provided {@code token},
     * or {@code null} if not found.
     *
     * @param token     the token credential
     * @param tokenType the {@link OAuth2TokenType token type}
     * @return the {@link OAuth2Authorization} if found, otherwise {@code null}
     */
    @Nullable
    OAuth2Authorization findByToken(String token, @Nullable OAuth2TokenType tokenType);

}
