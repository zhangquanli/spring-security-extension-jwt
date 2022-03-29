package com.github.zhangquanli.security.oauth2.server.authorization.client;

import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
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
        Assert.notEmpty(registrations, "registrations cannot be empty");
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

    @Nullable
    @Override
    public RegisteredClient findByClientId(String clientId) {
        Assert.hasText(clientId, "clientId cannot be empty");
        return clientIdRegistrationMap.get(clientId);
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
