package com.github.zhangquanli.security.oauth2.server.authorization.context;

import com.github.zhangquanli.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;

import java.util.function.Supplier;

/**
 * A context that holds information of the Provider.
 *
 * @author Joe Grandja
 * @see ProviderSettings
 * @see ProviderContextHolder
 */
public final class ProviderContext {
    private final ProviderSettings providerSettings;
    private final Supplier<String> issuerSupplier;

    /**
     * Constructs a {@code ProviderContext} using the provided parameters.
     *
     * @param providerSettings the provider settings
     * @param issuerSupplier   a {@code Supplier} for the {@code URL} of the Provider's issuer identifier
     */
    public ProviderContext(ProviderSettings providerSettings, @Nullable Supplier<String> issuerSupplier) {
        Assert.notNull(providerSettings, "providerSettings cannot be null");
        this.providerSettings = providerSettings;
        this.issuerSupplier = issuerSupplier;
    }

    /**
     * Returns the {@link ProviderSettings}.
     *
     * @return the {@link ProviderSettings}
     */
    public ProviderSettings getProviderSettings() {
        return this.providerSettings;
    }

    /**
     * Returns the {@code URL} of the Provider's issuer identifier.
     * The issuer identifier is resolved from the constructor parameter {@code Supplier<String>}
     * or if not provided then defaults to {@link ProviderSettings#getIssuer()}.
     *
     * @return the {@code URL} of the Provider's issuer identifier
     */
    public String getIssuer() {
        return this.issuerSupplier != null ?
                this.issuerSupplier.get() :
                getProviderSettings().getIssuer();
    }
}
