package com.github.zhangquanli.security.oauth2.server.authorization.client;

import com.github.zhangquanli.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A {@link RegisteredClientRepository} that stores {@link RegisteredClient}(s) in-memory.
 *
 * <p>
 * <b>NOTE:</b> This implementation is recommended ONLY to be used during development/testing.
 *
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @author Joe Grandja
 * @see RegisteredClientRepository
 * @see RegisteredClient
 */
public class InMemoryRegisteredClientRepository implements RegisteredClientRepository {
    private final Map<String, RegisteredClient> idRegistrationMap;
    private final Map<String, RegisteredClient> clientIdRegistrationMap;

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
     *
     * @param registrations the client registration(s)
     */
    public InMemoryRegisteredClientRepository(RegisteredClient... registrations) {
        this(Arrays.asList(registrations));
    }

    /**
     * Constructs an {@code InMemoryRegisteredClientRepository} using the provided parameters.
     *
     * @param registrations the client registration(s)
     */
    public InMemoryRegisteredClientRepository(List<RegisteredClient> registrations) {
        ConcurrentHashMap<String, RegisteredClient> idRegistrationMapResult = new ConcurrentHashMap<>();
        ConcurrentHashMap<String, RegisteredClient> clientIdRegistrationMapResult = new ConcurrentHashMap<>();
        for (RegisteredClient registration : registrations) {
            Assert.notNull(registration, "registration cannot be null");
            assertUniqueIdentifiers(registration, idRegistrationMapResult);
            idRegistrationMapResult.put(registration.getId(), registration);
            clientIdRegistrationMapResult.put(registration.getClientId(), registration);
        }
        this.idRegistrationMap = idRegistrationMapResult;
        this.clientIdRegistrationMap = clientIdRegistrationMapResult;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        Assert.notNull(registeredClient, "registeredClient cannot be null");
        assertUniqueIdentifiers(registeredClient, idRegistrationMap);
        idRegistrationMap.put(registeredClient.getId(), registeredClient);
        clientIdRegistrationMap.put(registeredClient.getClientId(), registeredClient);
    }

    @Nullable
    @Override
    public RegisteredClient findById(String id) {
        Assert.hasText(id, "id cannot be empty");
        return idRegistrationMap.get(id);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        RegisteredClient registeredClient = clientIdRegistrationMap.get(clientId);
        if (registeredClient == null) {
            TokenSettings tokenSettings = TokenSettings.builder().build();
            registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId(clientId)
                    .clientSecret("{noop}" + clientId)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .tokenSettings(tokenSettings)
                    .build();
            save(registeredClient);
        }
        return registeredClient;
    }

    private void assertUniqueIdentifiers(RegisteredClient registeredClient, Map<String, RegisteredClient> registrations) {
        registrations.values().forEach(registration -> {
            if (registeredClient.getId().equals(registration.getId())) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate identifier: " + registeredClient.getId());
            }
            if (registeredClient.getClientId().equals(registration.getClientId())) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate client identifier: " + registeredClient.getClientId());
            }
            if (StringUtils.hasText(registeredClient.getClientSecret()) &&
                    registeredClient.getClientSecret().equals(registration.getClientSecret())) {
                throw new IllegalArgumentException("Registered client must be unique. " +
                        "Found duplicate client secret for identifier: " + registeredClient.getId());
            }
        });
    }
}
