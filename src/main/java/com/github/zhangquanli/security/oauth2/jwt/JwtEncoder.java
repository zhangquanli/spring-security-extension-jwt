package com.github.zhangquanli.security.oauth2.jwt;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

/**
 * Implementations of this interface are responsible for encoding
 * a JSON Web Token (JWT) to it's compact claims representation format.
 * <p>
 * JWTs may be represented using the JWS Compact Serialization format for a
 * JSON Web Signature (JWS) structure or JWE Compact Serialization format for a
 * JSON Web Encryption (JWE) structure. Therefore, implementors are responsible
 * for signing a JWS and/or encrypting a JWE.
 *
 * @see Jwt
 * @see JoseHeader
 * @see JwtClaimsSet
 * @see JwtDecoder
 * @see <a href="https://tools.ietf.org/html/rfc7519" target="_blank">JSON Web Token (JWT)</a>
 * @see <a href="https://tools.ietf.org/html/rfc7515" target="_blank">JSON Web Signature (JWS)</a>
 * @see <a href="https://tools.ietf.org/html/rfc7516" target="_blank">JSON Web Encryption (JWE)</a>
 * @see <a href="https://tools.ietf.org/html/rfc7515#section-3.1" target="_blank">JWS Compact Serialization</a>
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-3.1" target="_blank" >JWE Compact Serialization</a>
 */
@FunctionalInterface
public interface JwtEncoder {
    /**
     * Encode the JWT to it's compact claims representation format.
     *
     * @param headers the JOSE header
     * @param claims  the JWT Claims Set
     * @return a {@link Jwt}
     * @throws JwtException if an error occurs while attempting to encode the JWT
     */
    Jwt encode(JoseHeader headers, JwtClaimsSet claims) throws JwtException;
}
