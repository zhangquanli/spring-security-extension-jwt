package com.github.zhangquanli.security.oauth2.server.authorization.client;

import com.github.zhangquanli.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * A representation of a client registration with an OAuth 2.0 Authorization Server.
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @see <a href="https://tools.ietf.org/html/rfc6749#section-2" target="_blank">
 * Section 2 Client Registration</a>
 */
public class RegisteredClient implements Serializable {
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    private Set<ClientAuthenticationMethod> clientAuthenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> scopes;
    private TokenSettings tokenSettings;

    protected RegisteredClient() {
    }

    /**
     * Returns the identifier for the registration.
     *
     * @return the identifier for the registration
     */
    public String getId() {
        return id;
    }

    /**
     * Returns the client identifier.
     *
     * @return the client identifier
     */
    public String getClientId() {
        return clientId;
    }

    /**
     * Returns the time at which the client identifier was issued.
     *
     * @return the time at which the client identifier was issued
     */
    @Nullable
    public Instant getClientIdIssuedAt() {
        return clientIdIssuedAt;
    }

    /**
     * Returns the client secret or {@code null} if not available.
     *
     * @return the client secret or {@code null} if not available
     */
    @Nullable
    public String getClientSecret() {
        return clientSecret;
    }

    /**
     * Returns the time at which the client secret expires or {@code null} if it does not expire.
     *
     * @return the time at which the client secret expires or {@code null} if it does not expire
     */
    @Nullable
    public Instant getClientSecretExpiresAt() {
        return clientSecretExpiresAt;
    }

    /**
     * Returns the client name.
     *
     * @return the client name
     */
    public String getClientName() {
        return clientName;
    }

    /**
     * Returns the {@link ClientAuthenticationMethod authentication method(s)} that the client may use.
     *
     * @return the {@code Set} of {@link ClientAuthenticationMethod authentication method(s)}
     */
    public Set<ClientAuthenticationMethod> getClientAuthenticationMethods() {
        return clientAuthenticationMethods;
    }

    /**
     * Returns the {@link AuthorizationGrantType authorization grant type(s)} that the client may use.
     *
     * @return the {@code Set} of {@link AuthorizationGrantType authorization grant type(s)}
     */
    public Set<AuthorizationGrantType> getAuthorizationGrantTypes() {
        return authorizationGrantTypes;
    }

    /**
     * Returns the scope(s) that the client may use.
     *
     * @return the {@code Set} of scope(s)
     */
    public Set<String> getScopes() {
        return scopes;
    }

    /**
     * Returns the {@link TokenSettings token configuration settings}.
     *
     * @return the {@link TokenSettings}
     */
    public TokenSettings getTokenSettings() {
        return this.tokenSettings;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        RegisteredClient that = (RegisteredClient) obj;
        return Objects.equals(this.id, that.id) &&
                Objects.equals(this.clientId, that.clientId) &&
                Objects.equals(this.clientIdIssuedAt, that.clientIdIssuedAt) &&
                Objects.equals(this.clientSecret, that.clientSecret) &&
                Objects.equals(this.clientSecretExpiresAt, that.clientSecretExpiresAt) &&
                Objects.equals(this.clientName, that.clientName) &&
                Objects.equals(this.clientAuthenticationMethods, that.clientAuthenticationMethods) &&
                Objects.equals(this.authorizationGrantTypes, that.authorizationGrantTypes) &&
                Objects.equals(this.scopes, that.scopes) &&
                Objects.equals(this.tokenSettings, that.tokenSettings);
    }

    @Override
    public int hashCode() {
        return Objects.hash(this.id, this.clientId, this.clientIdIssuedAt, this.clientSecret, this.clientSecretExpiresAt,
                this.clientName, this.clientAuthenticationMethods, this.authorizationGrantTypes, this.scopes, this.tokenSettings);
    }

    @Override
    public String toString() {
        return "RegisteredClient {" +
                "id='" + this.id + '\'' +
                ", clientId='" + this.clientId + '\'' +
                ", clientName='" + this.clientName + '\'' +
                ", clientAuthenticationMethods=" + this.clientAuthenticationMethods +
                ", authorizationGrantTypes=" + this.authorizationGrantTypes +
                ", scopes=" + this.scopes +
                ", tokenSettings=" + this.tokenSettings +
                '}';
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided registration identifier.
     *
     * @param id the identifier for the registration
     * @return the {@link Builder}
     */
    public static Builder withId(String id) {
        Assert.hasText(id, "id cannot be empty");
        return new Builder(id);
    }

    /**
     * Returns a new {@link Builder}, initialized with the values from the provided {@link RegisteredClient}.
     *
     * @param registeredClient the {@link RegisteredClient} used for initializing the {@link Builder}
     * @return the {@link Builder}
     */
    public static Builder from(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        return new Builder(registeredClient);
    }

    /**
     * A builder for {@link RegisteredClient}.
     */
    public static class Builder implements Serializable {
        private String id;
        private String clientId;
        private Instant clientIdIssuedAt;
        private String clientSecret;
        private Instant clientSecretExpiresAt;
        private String clientName;
        private final Set<ClientAuthenticationMethod> clientAuthenticationMethods = new HashSet<>();
        private final Set<AuthorizationGrantType> authorizationGrantTypes = new HashSet<>();
        private final Set<String> scopes = new HashSet<>();
        private TokenSettings tokenSettings;

        protected Builder(String id) {
            this.id = id;
        }

        protected Builder(RegisteredClient registeredClient) {
            this.id = registeredClient.getId();
            this.clientId = registeredClient.getClientId();
            this.clientIdIssuedAt = registeredClient.getClientIdIssuedAt();
            this.clientSecret = registeredClient.getClientSecret();
            this.clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt();
            this.clientName = registeredClient.getClientName();
            if (!CollectionUtils.isEmpty(registeredClient.getClientAuthenticationMethods())) {
                this.clientAuthenticationMethods.addAll(registeredClient.getClientAuthenticationMethods());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getAuthorizationGrantTypes())) {
                this.authorizationGrantTypes.addAll(registeredClient.getAuthorizationGrantTypes());
            }
            if (!CollectionUtils.isEmpty(registeredClient.getScopes())) {
                this.scopes.addAll(registeredClient.getScopes());
            }
            this.tokenSettings = TokenSettings.withSettings(registeredClient.getTokenSettings().getSettings()).build();
        }

        /**
         * Sets the identifier for the registration.
         *
         * @param id the identifier for the registration
         * @return the {@link Builder}
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /**
         * Sets the client identifier.
         *
         * @param clientId the client identifier
         * @return the {@link Builder}
         */
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /**
         * Sets the time at which the client identifier was issued.
         *
         * @param clientIdIssuedAt the time at which the client identifier was issued
         * @return the {@link Builder}
         */
        public Builder clientIdIssuedAt(Instant clientIdIssuedAt) {
            this.clientIdIssuedAt = clientIdIssuedAt;
            return this;
        }

        /**
         * Sets the client secret.
         *
         * @param clientSecret the client secret
         * @return the {@link Builder}
         */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        /**
         * Sets the time at which the client secret expires or {@code null} if it does not expire.
         *
         * @param clientSecretExpiresAt the time at which the client secret expires or {@code null} if it does not expire
         * @return the {@link Builder}
         */
        public Builder clientSecretExpiresAt(Instant clientSecretExpiresAt) {
            this.clientSecretExpiresAt = clientSecretExpiresAt;
            return this;
        }

        /**
         * Sets the client name.
         *
         * @param clientName the client name
         * @return the {@link Builder}
         */
        public Builder clientName(String clientName) {
            this.clientName = clientName;
            return this;
        }

        /**
         * Adds an {@link ClientAuthenticationMethod authentication method}
         * the client may use when authenticating with the authorization server.
         *
         * @param clientAuthenticationMethod the authentication method
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
            this.clientAuthenticationMethods.add(clientAuthenticationMethod);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link ClientAuthenticationMethod authentication method(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param clientAuthenticationMethodsConsumer a {@code Consumer} of the authentication method(s)
         * @return the {@link Builder}
         */
        public Builder clientAuthenticationMethods(
                Consumer<Set<ClientAuthenticationMethod>> clientAuthenticationMethodsConsumer) {
            clientAuthenticationMethodsConsumer.accept(this.clientAuthenticationMethods);
            return this;
        }

        /**
         * Adds an {@link AuthorizationGrantType authorization grant type} the client may use.
         *
         * @param authorizationGrantType the authorization grant type
         * @return the {@link Builder}
         */
        public Builder authorizationGrantType(AuthorizationGrantType authorizationGrantType) {
            this.authorizationGrantTypes.add(authorizationGrantType);
            return this;
        }

        /**
         * A {@code Consumer} of the {@link AuthorizationGrantType authorization grant type(s)}
         * allowing the ability to add, replace, or remove.
         *
         * @param authorizationGrantTypesConsumer a {@code Consumer} of the authorization grant type(s)
         * @return the {@link Builder}
         */
        public Builder authorizationGrantTypes(Consumer<Set<AuthorizationGrantType>> authorizationGrantTypesConsumer) {
            authorizationGrantTypesConsumer.accept(this.authorizationGrantTypes);
            return this;
        }

        /**
         * Adds a scope the client may use.
         *
         * @param scope the scope
         * @return the {@link Builder}
         */
        public Builder scope(String scope) {
            this.scopes.add(scope);
            return this;
        }

        /**
         * A {@code Consumer} of the scope(s)
         * allowing the ability to add, replace, or remove.
         *
         * @param scopesConsumer a {@link Consumer} of the scope(s)
         * @return the {@link Builder}
         */
        public Builder scopes(Consumer<Set<String>> scopesConsumer) {
            scopesConsumer.accept(this.scopes);
            return this;
        }

        /**
         * Sets the {@link TokenSettings token configuration settings}.
         *
         * @param tokenSettings the token configuration settings
         * @return the {@link Builder}
         */
        public Builder tokenSettings(TokenSettings tokenSettings) {
            this.tokenSettings = tokenSettings;
            return this;
        }

        /**
         * Builds a new {@link RegisteredClient}.
         *
         * @return a {@link RegisteredClient}
         */
        public RegisteredClient build() {
            Assert.hasText(this.clientId, "clientId cannot be empty");
            Assert.notEmpty(this.authorizationGrantTypes, "authorizationGrantTypes cannot be empty");
            if (!StringUtils.hasText(this.clientName)) {
                this.clientName = this.id;
            }
            if (CollectionUtils.isEmpty(this.clientAuthenticationMethods)) {
                this.clientAuthenticationMethods.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }
            validateScopes();
            return create();
        }

        private RegisteredClient create() {
            RegisteredClient registeredClient = new RegisteredClient();

            registeredClient.id = this.id;
            registeredClient.clientId = this.clientId;
            registeredClient.clientIdIssuedAt = this.clientIdIssuedAt;
            registeredClient.clientSecret = this.clientSecret;
            registeredClient.clientSecretExpiresAt = this.clientSecretExpiresAt;
            registeredClient.clientName = this.clientName;
            registeredClient.clientAuthenticationMethods = Collections.unmodifiableSet(
                    new HashSet<>(this.clientAuthenticationMethods));
            registeredClient.authorizationGrantTypes = Collections.unmodifiableSet(
                    new HashSet<>(this.authorizationGrantTypes));
            registeredClient.scopes = Collections.unmodifiableSet(
                    new HashSet<>(this.scopes));
            registeredClient.tokenSettings = this.tokenSettings != null ?
                    this.tokenSettings : TokenSettings.builder().build();

            return registeredClient;
        }

        private void validateScopes() {
            if (CollectionUtils.isEmpty(this.scopes)) {
                return;
            }

            for (String scope : this.scopes) {
                Assert.isTrue(validateScope(scope), "scope \"" + scope + "\" contains invalid characters");
            }
        }

        private static boolean validateScope(String scope) {
            return scope == null ||
                    scope.chars().allMatch(c -> withinTheRangeOf(c, 0x21, 0x21) ||
                            withinTheRangeOf(c, 0x23, 0x5B) ||
                            withinTheRangeOf(c, 0x5D, 0x7E));
        }

        private static boolean withinTheRangeOf(int c, int min, int max) {
            return c >= min && c <= max;
        }
    }
}
