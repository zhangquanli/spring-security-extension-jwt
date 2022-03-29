package com.github.zhangquanli.security.oauth2.server.authorization.client;

import org.springframework.lang.Nullable;

/**
 * A repository for OAuth 2.0 {@link RegisteredClient}(s).
 *
 * @author Joe Grandja
 * @author Anoop Garlapati
 * @author Ovidiu Popa
 * @see RegisteredClient
 */
public interface RegisteredClientRepository {

    /**
     * Saves the registered client.
     *
     * <p>
     * IMPORTANT: Sensitive information should be encoded externally from the implementation, e.g. {@link RegisteredClient#getClientSecret()}
     *
     * @param registeredClient the {@link RegisteredClient}
     */
    void save(RegisteredClient registeredClient);

    /**
     * Returns the registered client identified by the provided {@code id},
     * or {@code null} if not found.
     *
     * @param id the registration identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    @Nullable
    RegisteredClient findById(String id);

    /**
     * Returns the registered client identified by the provided {@code clientId},
     * or {@code null} if not found.
     *
     * @param clientId the client identifier
     * @return the {@link RegisteredClient} if found, otherwise {@code null}
     */
    @Nullable
    RegisteredClient findByClientId(String clientId);

}
