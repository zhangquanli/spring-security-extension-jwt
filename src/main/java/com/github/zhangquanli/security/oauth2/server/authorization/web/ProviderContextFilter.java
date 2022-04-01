package com.github.zhangquanli.security.oauth2.server.authorization.web;

import com.github.zhangquanli.security.oauth2.server.authorization.config.ProviderSettings;
import com.github.zhangquanli.security.oauth2.server.authorization.context.ProviderContext;
import com.github.zhangquanli.security.oauth2.server.authorization.context.ProviderContextHolder;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A {@code Filter} that associates the {@link ProviderContext} to the {@link ProviderContextHolder}.
 *
 * @author Joe Grandja
 * @see ProviderContext
 * @see ProviderContextHolder
 * @see ProviderSettings
 */
public class ProviderContextFilter extends OncePerRequestFilter {
    private final ProviderSettings providerSettings;

    /**
     * Constructs a {@code ProviderContextFilter} using the provided parameters.
     *
     * @param providerSettings the provider settings
     */
    public ProviderContextFilter(ProviderSettings providerSettings) {
        Assert.notNull(providerSettings, "providerSettings cannot be null");
        this.providerSettings = providerSettings;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            ProviderContext providerContext = new ProviderContext(providerSettings,
                    () -> resolveIssuer(providerSettings, request));
            ProviderContextHolder.setProviderContext(providerContext);
            filterChain.doFilter(request, response);
        } finally {
            ProviderContextHolder.resetProviderContext();
        }
    }

    private static String resolveIssuer(ProviderSettings providerSettings, HttpServletRequest request) {
        return providerSettings.getIssuer() != null ?
                providerSettings.getIssuer() :
                getContextPath(request);
    }


    private static String getContextPath(HttpServletRequest request) {
        return UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
                .replacePath(request.getContextPath())
                .replaceQuery(null)
                .fragment(null)
                .build()
                .toUriString();
    }
}
