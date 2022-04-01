package com.github.zhangquanli.security.oauth2.server.authorization.context;

import com.github.zhangquanli.security.oauth2.server.authorization.web.ProviderContextFilter;

/**
 * A holder of {@link ProviderContext} that associates it with the current thread using a {@code ThreadLocal}.
 *
 * @author Joe Grandja
 * @see ProviderContext
 * @see ProviderContextFilter
 */
public final class ProviderContextHolder {
    private static final ThreadLocal<ProviderContext> holder = new ThreadLocal<>();

    private ProviderContextHolder() {
    }

    /**
     * Returns the {@link ProviderContext} bound to the current thread.
     *
     * @return the {@link ProviderContext}
     */
    public static ProviderContext getProviderContext() {
        return holder.get();
    }

    /**
     * Bind the given {@link ProviderContext} to the current thread.
     *
     * @param providerContext the {@link ProviderContext}
     */
    public static void setProviderContext(ProviderContext providerContext) {
        if (providerContext == null) {
            resetProviderContext();
        } else {
            holder.set(providerContext);
        }
    }

    /**
     * Reset the {@link ProviderContext} bound to the current thread.
     */
    public static void resetProviderContext() {
        holder.remove();
    }
}
