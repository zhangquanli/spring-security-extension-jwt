package com.github.zhangquanli.security.oauth2.jwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimAccessor;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * The {@link Jwt JWT} Claims Set is a JSON object representing the claims conveyed by a JSON Web Token.
 *
 * @see Jwt
 * @see JwtClaimAccessor
 * @see <a href="https://tools.ietf.org/html/rfc7519#section-4" target="_blank">JWT Claims Set</a>
 */
public final class JwtClaimsSet implements JwtClaimAccessor {
    private final Map<String, Object> claims;

    private JwtClaimsSet(Map<String, Object> claims) {
        this.claims = Collections.unmodifiableMap(new HashMap<>(claims));
    }

    @Override
    public Map<String, Object> getClaims() {
        return claims;
    }

    /**
     * Returns a new {@link Builder}.
     *
     * @return the {@link Builder}
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Returns a new {@link Builder}, initialized with the provided {@code claims}.
     *
     * @param claims a JWT claims set
     * @return the {@link Builder}
     */
    public static Builder from(JwtClaimsSet claims) {
        return new Builder(claims);
    }

    /**
     * A builder for {@link JwtClaimsSet}.
     */
    public static final class Builder {
        private final Map<String, Object> claims = new HashMap<>();

        private Builder() {
        }

        private Builder(JwtClaimsSet claims) {
            Assert.notNull(claims, "claims cannot be null");
            this.claims.putAll(claims.getClaims());
        }

        /**
         * Sets the issuer {@code (iss)} claim, which identifies the principal that issued the JWT.
         *
         * @param issuer the issuer identifier
         * @return the {@link Builder}
         */
        public Builder issuer(String issuer) {
            return claim(JwtClaimNames.ISS, issuer);
        }

        /**
         * Sets the subject {@code (sub)} claim, which identifies the
         *
         * @param subject the subject identifier
         * @return the {@link Builder}
         */
        public Builder subject(String subject) {
            return claim(JwtClaimNames.SUB, subject);
        }

        /**
         * Sets the audience {@code (aud)} claim, which identifies the recipient(s) that the JWT is intended fro.
         *
         * @param audience the audience that this JWT is intended for
         * @return the {@link Builder}
         */
        public Builder audience(List<String> audience) {
            return claim(JwtClaimNames.AUD, audience);
        }

        /**
         * Sets the expiration time {@code (exp)} claim, which identifies the time
         * on or after which the JWT MUST NOT be accepted for processing.
         *
         * @param expiresAt the time on or after which the JWT MUST NOT be accepted for processing
         * @return the {@link Builder}
         */
        public Builder expiresAt(Instant expiresAt) {
            return claim(JwtClaimNames.EXP, expiresAt);
        }


        /**
         * Sets the not before {@code (nbf)} claim, which identifies the time
         * before which the JWT MUST NOT be accepted for processing.
         *
         * @param notBefore the time before which the JWT MUST NOT be accepted for processing
         * @return the {@link Builder}
         */
        public Builder notBefore(Instant notBefore) {
            return claim(JwtClaimNames.NBF, notBefore);
        }

        /**
         * Sets the issued at {@code (iat)} claim, which identifies the time at which the JWT was issued.
         *
         * @param issuedAt the time at which the JWT was issued
         * @return the {@link Builder}
         */
        public Builder issuedAt(Instant issuedAt) {
            return claim(JwtClaimNames.IAT, issuedAt);
        }

        /**
         * Sets the JWT ID {@code (jti)} claim, which provides a unique identifier for the JWT.
         *
         * @param jti the unique identifier for the JWT
         * @return the {@link Builder}
         */
        public Builder id(String jti) {
            return claim(JwtClaimNames.JTI, jti);
        }

        /**
         * Sets the claim
         *
         * @param name  the claim name
         * @param value the claim value
         * @return the {@link Builder}
         */
        public Builder claim(String name, Object value) {
            Assert.hasText(name, "name cannot be empty");
            Assert.notNull(value, "value cannot be null");
            claims.put(name, value);
            return this;
        }

        /**
         * A {@code Consumer} to be provided access to the claims set
         * allowing to ability to add, replace, or remove.
         *
         * @param claimsConsumer a {@code Consumer} of the claims set
         * @return the {@link Builder}
         */
        public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
            claimsConsumer.accept(claims);
            return this;
        }

        /**
         * Builds a ne {@link JwtClaimsSet}
         *
         * @return a {@link JwtClaimsSet}
         */
        public JwtClaimsSet build() {
            Assert.notEmpty(claims, "claims cannot be empty");
            return new JwtClaimsSet(claims);
        }
    }
}
