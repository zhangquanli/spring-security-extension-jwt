package com.github.zhangquanli.security.token.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.stream.Collectors;

/**
 * Extracts the {@link GrantedAuthority}s from scope attributes typically found in a
 * {@link Jwt}.
 *
 * @author Eric Deandrea
 * @since 5.2
 */
public class JwtGrantedAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    private final Log logger = LogFactory.getLog(getClass());
    private static final String DEFAULT_AUTHORITY_PREFIX = "SCOPE_";
    private static final Collection<String> WELL_KNOWN_AUTHORITIES_CLAIM_NAMES = Arrays.asList("scope", "scp");

    private String authorityPrefix = DEFAULT_AUTHORITY_PREFIX;
    private String authoritiesClaimName;

    /**
     * Extract {@link GrantedAuthority}s from the given {@link Jwt}.
     *
     * @param jwt The {@link Jwt} token
     * @return The {@link GrantedAuthority authorities} read from the token scopes
     */
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        return getAuthorities(jwt).stream()
                .map(authority -> new SimpleGrantedAuthority(authorityPrefix + authority))
                .collect(Collectors.toList());
    }

    /**
     * Sets the prefix to use for {@link GrantedAuthority authorities} mapped by this
     * converter. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#DEFAULT_AUTHORITY_PREFIX}.
     *
     * @param authorityPrefix The authority prefix
     * @see 5.2
     */
    public void setAuthorityPrefix(String authorityPrefix) {
        Assert.notNull(authorityPrefix, "authorityPrefix cannot be null");
        this.authorityPrefix = authorityPrefix;
    }

    /**
     * Sets the name of token claim to use for mapping {@link GrantedAuthority
     * authorities} by this converter. Defaults to
     * {@link JwtGrantedAuthoritiesConverter#WELL_KNOWN_AUTHORITIES_CLAIM_NAMES}.
     *
     * @param authoritiesClaimName The token claim name to map authorities
     * @since 5.2
     */
    public void setAuthoritiesClaimName(String authoritiesClaimName) {
        Assert.hasText(authoritiesClaimName, "authoritiesClaimName cannot be empty");
        this.authoritiesClaimName = authoritiesClaimName;
    }

    private Collection<String> getAuthorities(Jwt jwt) {
        String claimName = getAuthoritiesClaimName(jwt);
        if (claimName == null) {
            logger.trace("Returning no authorities since could not found any claims that might contain scopes");
            return Collections.emptyList();
        }
        if (logger.isTraceEnabled()) {
            logger.trace(LogMessage.format("Looking for scopes in claim %s", claimName));
        }
        Object authorities = jwt.getClaim(claimName);
        if (authorities instanceof String) {
            if (StringUtils.hasText((String) authorities)) {
                return Arrays.asList(((String) authorities).split(" "));
            }
            return Collections.emptyList();
        }
        if (authorities instanceof Collection) {
            return ((Collection<?>) authorities).stream()
                    .map(Object::toString).collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    private String getAuthoritiesClaimName(Jwt jwt) {
        if (authoritiesClaimName != null) {
            return authoritiesClaimName;
        }
        for (String claimName : WELL_KNOWN_AUTHORITIES_CLAIM_NAMES) {
            if (jwt.containsClaim(claimName)) {
                return claimName;
            }
        }
        return null;
    }
}
