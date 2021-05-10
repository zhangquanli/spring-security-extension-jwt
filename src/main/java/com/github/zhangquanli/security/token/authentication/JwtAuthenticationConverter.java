package com.github.zhangquanli.security.token.authentication;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * @author Rob Winch
 * @author Josh Cummings
 * @author Evgeniy Cheban
 * @since 5.1
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();
    private String principalClaimName;

    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = extractAuthorities(jwt);
        if (principalClaimName == null) {
            return new JwtAuthenticationToken(jwt, authorities);
        }
        String name = jwt.getClaim(principalClaimName);
        return new JwtAuthenticationToken(jwt, authorities, name);
    }

    /**
     * Extracts the {@link GrantedAuthority}s from scope attribute typically found in a
     * {@link Jwt}
     *
     * @param jwt the token
     * @return The collection of {@link GrantedAuthority}s found on the token
     */
    protected Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
        return jwtGrantedAuthoritiesConverter.convert(jwt);
    }

    /**
     * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;}
     * to use. Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @param jwtGrantedAuthoritiesConverter The converter
     * @see JwtGrantedAuthoritiesConverter
     * @since 5.2
     */
    public void setJwtGrantedAuthoritiesConverter(
            Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter) {
        Assert.notNull(jwtGrantedAuthoritiesConverter, "jwtGrantedAuthoritiesConverter cannot be null");
        this.jwtGrantedAuthoritiesConverter = jwtGrantedAuthoritiesConverter;
    }

    /**
     * Sets to principal claim name. Defaults to {@link JwtClaimNames#SUB}.
     *
     * @param principalClaimName The principal claim name
     * @since 5.4
     */
    public void setPrincipalClaimName(String principalClaimName) {
        Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
        this.principalClaimName = principalClaimName;
    }
}
