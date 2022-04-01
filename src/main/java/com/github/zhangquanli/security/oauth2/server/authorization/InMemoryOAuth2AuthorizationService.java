package com.github.zhangquanli.security.oauth2.server.authorization;

import com.github.zhangquanli.security.oauth2.core.OAuth2TokenType;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * An {@link OAuth2AuthorizationService} that stores {@link OAuth2Authorization}'s in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation should ONLY be used during development/testing.
 *
 * @author Krisztian Toth
 * @author Joe Grandja
 * @see OAuth2AuthorizationService
 */
public class InMemoryOAuth2AuthorizationService implements OAuth2AuthorizationService {
    private final Map<String, OAuth2Authorization> authorizations = new ConcurrentHashMap<>();

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationService}.
     */
    public InMemoryOAuth2AuthorizationService() {
        this(Collections.emptyList());
    }

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
     *
     * @param authorizations the authorization(s)
     */
    public InMemoryOAuth2AuthorizationService(OAuth2Authorization... authorizations) {
        this(Arrays.asList(authorizations));
    }

    /**
     * Constructs an {@code InMemoryOAuth2AuthorizationService} using the provided parameters.
     *
     * @param authorizations the authorization(s)
     */
    public InMemoryOAuth2AuthorizationService(List<OAuth2Authorization> authorizations) {
        Assert.notNull(authorizations, "authorizations cannot be null");
        authorizations.forEach(authorization -> {
            Assert.notNull(authorization, "authorization cannot be null");
            Assert.isTrue(!this.authorizations.containsKey(authorization.getId()),
                    "This authorization must be unique. Found duplicate identifier: " + authorization.getId());
            this.authorizations.put(authorization.getId(), authorization);
        });
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizations.put(authorization.getId(), authorization);
    }

    @Override
    public void remove(OAuth2Authorization authorization) {
        Assert.notNull(authorization, "authorization cannot be null");
        authorizations.remove(authorization.getId(), authorization);
    }

    @Nullable
    @Override
    public OAuth2Authorization findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return authorizations.get(id);
    }

    @Nullable
    @Override
    public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
        Assert.hasText(token, "token cannot be empty");
        for (OAuth2Authorization authorization : authorizations.values()) {
            if (hasToken(authorization, token, tokenType)) {
                return authorization;
            }
        }
        return null;
    }

    private static boolean hasToken(OAuth2Authorization authorization, String token, @Nullable OAuth2TokenType tokenType) {
        if (tokenType == null) {
            return matchesAccessToken(authorization, token) ||
                    matchesRefreshToken(authorization, token);
        } else if (tokenType == OAuth2TokenType.ACCESS_TOKEN) {
            return matchesAccessToken(authorization, token);
        } else if (tokenType == OAuth2TokenType.REFRESH_TOKEN) {
            return matchesRefreshToken(authorization, token);
        }
        return false;
    }

    private static boolean matchesAccessToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
                authorization.getToken(OAuth2AccessToken.class);
        return accessToken != null && accessToken.getToken().getTokenValue().equals(token);
    }

    private static boolean matchesRefreshToken(OAuth2Authorization authorization, String token) {
        OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
                authorization.getToken(OAuth2RefreshToken.class);
        return refreshToken != null && refreshToken.getToken().getTokenValue().equals(token);
    }
}
