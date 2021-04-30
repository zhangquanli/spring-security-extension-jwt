package com.github.zhangquanli.security.jwt;

/**
 * The Registered Header Parameter Names defined by the JSON Web Token (JWT),
 * JSON Web Signature (JWS) and JSON Web Encryption (JWE) specifications
 * that may be contained in the JOSE Header of a JWT.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7519#section-5" target="_blank">JWT JOSE Header</a>
 * @see <a href="https://tools.ietf.org/html/rfc7515#section-4" target="_blank">JWS JOSE Header</a>
 * @see <a href="https://tools.ietf.org/html/rfc7516#section-4" target="_blank">JWE JOSE Header</a>
 */
public interface JoseHeaderNames {
    /**
     * {@code alg} - the algorithm header identifies the cryptographic algorithm used to secure a JWS or JWE
     */
    String ALG = "alg";

    /**
     * {@code jku} - the JWK Set URL header is a URI that refers to a resource for a set of JSON-encoded public keys,
     * one of which corresponds to the key used to digitally sign a JWS or encrypt a JWE
     */
    String JKU = "jku";

    /**
     * {@code jwk} - the JSON Web key header is the public key that corresponds to the key
     * used to digitally sign a JWS or encrypt a JWE
     */
    String JWK = "jwk";

    /**
     * {@code kid} - the key ID header is a hint indicating which key was used to secure a JWS or JWE
     */
    String KID = "kid";

    /**
     * {@code x5u} - the X.509 URL header is a URI that refers to a resource for the X.509 public key certificate
     * or certificate chain corresponding to the key used to digitally sign a JWS or encrypt a JWE
     */
    String X5U = "x5u";

    /**
     * {@code x5c} - the X.509 certificate chain header contains the X.509 public key certificate
     * or certificate chain corresponding to key used to digitally sign a JWS or encrypt a JWE
     */
    String X5C = "x5c";

    /**
     * {@code x5t} - the X.509 certificate SHA-1 thumbprint header is a base64url-encoded SHA-1 thumbprint (a.k.a. digest)
     * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign a JWS or encrypt a JWE
     */
    String X5T = "x5t";

    /**
     * {@code x5t#S256} - the X.509 certificate SHA-256 thumbprint header is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
     * of the DER encoding of the X.509 certificate corresponding to the key used to digitally sign a JWS or encrypt a JWE
     */
    String X5T_S256 = "x5t#S256";

    /**
     * {@code typ} - the type header is used by JWS/JWE applications to declare the media type of a JWS/JWE
     */
    String TYP = "typ";

    /**
     * {@code cty} - the content type header is used by JWS/JWE applications to declare the media type
     * of the secured content (the payload)
     */
    String CTY = "cty";

    /**
     * {@code crit} - the critical header indicates that extensions to the JWS/JWE/JWA specifications
     * are being used that MUST be understood and processed
     */
    String CRIT = "crit";
}
