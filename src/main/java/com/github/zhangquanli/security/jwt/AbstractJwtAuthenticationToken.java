package com.github.zhangquanli.security.jwt;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;

public abstract class AbstractJwtAuthenticationToken extends AbstractAuthenticationToken {
    private Jwt jwt;

    public AbstractJwtAuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
    }

    public void setJwt(Jwt jwt) {
        this.jwt = jwt;
    }

    public Jwt getJwt() {
        return jwt;
    }
}
