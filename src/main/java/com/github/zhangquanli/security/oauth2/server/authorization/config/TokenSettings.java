package com.github.zhangquanli.security.oauth2.server.authorization.config;

import org.springframework.util.Assert;

import java.time.Duration;
import java.util.Map;

/**
 * A facility for token configuration settings.
 *
 * @author Joe Grandja
 * @see AbstractSettings
 * @see ConfigurationSettingNames.Token
 */
public final class TokenSettings extends AbstractSettings {
    private TokenSettings(Map<String, Object> settings) {
        super(settings);
    }

    /**
     * Returns the time-to-live for an access token. The default is 5 minutes.
     *
     * @return the time-to-live for an access token
     */
    public Duration getAccessTokenTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE);
    }

    /**
     * Returns {@code true} if refresh tokens are reused when returning the access token response,
     * or {@code false} if a new refresh token is issued. The default is {@code true}.
     */
    public boolean isReuseRefreshTokens() {
        return getSetting(ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS);
    }

    /**
     * Returns the time-to-live for a refresh token. The default is 60 minutes.
     *
     * @return the time-to-live for a refresh token
     */
    public Duration getRefreshTokenTimeToLive() {
        return getSetting(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE);
    }

    /**
     * Constructs a new {@link Builder} with the default settings.
     *
     * @return the {@link Builder}
     */
    public static Builder builder() {
        return new Builder()
                .accessTokenTimeToLive(Duration.ofMinutes(5))
                .reuseRefreshTokens(true)
                .refreshTokenTimeToLive(Duration.ofMinutes(60));
    }

    /**
     * Constructs a new {@link Builder} with the provided settings.
     *
     * @param settings the settings to initialize the builder
     * @return the {@link Builder}
     */
    public static Builder withSettings(Map<String, Object> settings) {
        Assert.notEmpty(settings, "settings cannot be empty");
        return new Builder()
                .settings(s -> s.putAll(settings));
    }

    /**
     * A builder for {@link TokenSettings}.
     */
    public static class Builder extends AbstractBuilder<TokenSettings, Builder> {
        private Builder() {
        }

        /**
         * Set the time-to-live for an access token. Must be greater than {@code Duration.ZERO}.
         *
         * @param accessTokenTimeToLive the time-to-live for an access token
         * @return the {@link Builder} for further configuration
         */
        public Builder accessTokenTimeToLive(Duration accessTokenTimeToLive) {
            Assert.notNull(accessTokenTimeToLive, "accessTokeTimeToLive cannot be null");
            Assert.isTrue(accessTokenTimeToLive.getSeconds() > 0, "accessTokenTimeToLive must be greater than Duration.ZERO");
            return setting(ConfigurationSettingNames.Token.ACCESS_TOKEN_TIME_TO_LIVE, accessTokenTimeToLive);
        }

        /**
         * Set to {@code true} if refresh tokens are reused when returning the access token response,
         * or {@code false} if a new refresh token is issued.
         *
         * @param reuseRefreshTokens {@code true} to reuse refresh tokens, {@code false} to issue new refresh tokens
         * @return the {@link Builder} for further configuration
         */
        public Builder reuseRefreshTokens(boolean reuseRefreshTokens) {
            return setting(ConfigurationSettingNames.Token.REUSE_REFRESH_TOKENS, reuseRefreshTokens);
        }

        /**
         * Set the time-to-live for a refresh token. Must be greater than {@code Duration.ZERO}.
         *
         * @param refreshTokenTimeToLive the time-to-live for a refresh token
         * @return the {@link Builder} for further configuration
         */
        public Builder refreshTokenTimeToLive(Duration refreshTokenTimeToLive) {
            Assert.notNull(refreshTokenTimeToLive, "refreshTokenTimeToLive cannot be null");
            Assert.isTrue(refreshTokenTimeToLive.getSeconds() > 0, "refreshTokenTimeToLive must be greater than Duration.ZERO");
            return setting(ConfigurationSettingNames.Token.REFRESH_TOKEN_TIME_TO_LIVE, refreshTokenTimeToLive);
        }

        /**
         * Builds the {@link TokenSettings}.
         *
         * @return the {@link TokenSettings}
         */
        @Override
        public TokenSettings build() {
            return new TokenSettings(getSettings());
        }
    }
}
