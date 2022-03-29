package com.github.zhangquanli.security.oauth2.server.resource.authentication;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

import java.util.Collection;

/**
 * JwtAuthenticationConverter
 *
 * @author Rob Winch
 * @author Josh Cummings
 * @author Evgeniy Cheban
 */
public class JwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private Converter<Jwt, Collection<GrantedAuthority>> jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    private String principalClaimName;

    @Override
    public final AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = jwtGrantedAuthoritiesConverter.convert(jwt);
        if (principalClaimName == null) {
            return new JwtAuthenticationToken(jwt, authorities);
        }
        String name = jwt.getClaim(principalClaimName);
        return new JwtAuthenticationToken(jwt, authorities, name);
    }

    /**
     * Sets the {@link Converter Converter&lt;Jwt, Collection&lt;GrantedAuthority&gt;&gt;}
     * to use. Defaults to {@link JwtGrantedAuthoritiesConverter}.
     *
     * @param jwtGrantedAuthoritiesConverter The converter
     * @see JwtGrantedAuthoritiesConverter
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
     */
    public void setPrincipalClaimName(String principalClaimName) {
        Assert.hasText(principalClaimName, "principalClaimName cannot be empty");
        this.principalClaimName = principalClaimName;
    }

}
